"""Install reusable inventory metadata; immutable snapshot, no runtime seeding.

Revision ID: 0004_inventory_catalog
Revises: 0003_inventory
"""

from __future__ import annotations

import json

import sqlalchemy as sa
from alembic import op

revision = "0004_inventory_catalog"
down_revision = "0003_inventory"
branch_labels = None
depends_on = None

_SEED_JSON = r"""[
  {
    "kind": "fields",
    "key": "serial",
    "payload": {
      "key": "serial",
      "label": "Número de serie",
      "type": "text",
      "active": true,
      "required": false,
      "options": [],
      "unit": "",
      "hint": "",
      "maxLength": 500
    }
  },
  {
    "kind": "fields",
    "key": "cpu",
    "payload": {
      "key": "cpu",
      "label": "Procesador",
      "type": "text",
      "active": true,
      "required": false,
      "options": [],
      "unit": "",
      "hint": "",
      "maxLength": 500
    }
  },
  {
    "kind": "fields",
    "key": "ram",
    "payload": {
      "key": "ram",
      "label": "Memoria RAM",
      "type": "number",
      "active": true,
      "required": false,
      "options": [],
      "unit": "",
      "hint": "",
      "maxLength": 500
    }
  },
  {
    "kind": "fields",
    "key": "storage",
    "payload": {
      "key": "storage",
      "label": "Almacenamiento",
      "type": "text",
      "active": true,
      "required": false,
      "options": [],
      "unit": "",
      "hint": "",
      "maxLength": 500
    }
  },
  {
    "kind": "fields",
    "key": "os",
    "payload": {
      "key": "os",
      "label": "Sistema operativo",
      "type": "text",
      "active": true,
      "required": false,
      "options": [],
      "unit": "",
      "hint": "",
      "maxLength": 500
    }
  },
  {
    "kind": "fields",
    "key": "mac",
    "payload": {
      "key": "mac",
      "label": "Dirección MAC",
      "type": "text",
      "active": true,
      "required": false,
      "options": [],
      "unit": "",
      "hint": "",
      "maxLength": 500
    }
  },
  {
    "kind": "fields",
    "key": "firmware",
    "payload": {
      "key": "firmware",
      "label": "Firmware",
      "type": "text",
      "active": true,
      "required": false,
      "options": [],
      "unit": "",
      "hint": "",
      "maxLength": 500
    }
  },
  {
    "kind": "fields",
    "key": "ports",
    "payload": {
      "key": "ports",
      "label": "Puertos",
      "type": "number",
      "active": true,
      "required": false,
      "options": [],
      "unit": "",
      "hint": "",
      "maxLength": 500
    }
  },
  {
    "kind": "fields",
    "key": "rack",
    "payload": {
      "key": "rack",
      "label": "Rack / unidad",
      "type": "text",
      "active": true,
      "required": false,
      "options": [],
      "unit": "",
      "hint": "",
      "maxLength": 500
    }
  },
  {
    "kind": "fields",
    "key": "resolution",
    "payload": {
      "key": "resolution",
      "label": "Resolución",
      "type": "text",
      "active": true,
      "required": false,
      "options": [],
      "unit": "",
      "hint": "",
      "maxLength": 500
    }
  },
  {
    "kind": "fields",
    "key": "fovAngle",
    "payload": {
      "key": "fovAngle",
      "label": "Ángulo de visión",
      "type": "text",
      "active": true,
      "required": false,
      "options": [],
      "unit": "",
      "hint": "",
      "maxLength": 500
    }
  },
  {
    "kind": "fields",
    "key": "nightVision",
    "payload": {
      "key": "nightVision",
      "label": "Visión nocturna",
      "type": "boolean",
      "active": true,
      "required": false,
      "options": [],
      "unit": "",
      "hint": "",
      "maxLength": 500
    }
  },
  {
    "kind": "fields",
    "key": "poe",
    "payload": {
      "key": "poe",
      "label": "Alimentación PoE",
      "type": "boolean",
      "active": true,
      "required": false,
      "options": [],
      "unit": "",
      "hint": "",
      "maxLength": 500
    }
  },
  {
    "kind": "fields",
    "key": "upsCapacity",
    "payload": {
      "key": "upsCapacity",
      "label": "Capacidad",
      "type": "text",
      "active": true,
      "required": false,
      "options": [],
      "unit": "",
      "hint": "",
      "maxLength": 500
    }
  },
  {
    "kind": "fields",
    "key": "batteryLife",
    "payload": {
      "key": "batteryLife",
      "label": "Autonomía",
      "type": "text",
      "active": true,
      "required": false,
      "options": [],
      "unit": "",
      "hint": "",
      "maxLength": 500
    }
  },
  {
    "kind": "fields",
    "key": "vmHost",
    "payload": {
      "key": "vmHost",
      "label": "Host",
      "type": "text",
      "active": true,
      "required": false,
      "options": [],
      "unit": "",
      "hint": "",
      "maxLength": 500
    }
  },
  {
    "kind": "fields",
    "key": "vmCpu",
    "payload": {
      "key": "vmCpu",
      "label": "vCPU",
      "type": "number",
      "active": true,
      "required": false,
      "options": [],
      "unit": "",
      "hint": "",
      "maxLength": 500
    }
  },
  {
    "kind": "fields",
    "key": "vmRam",
    "payload": {
      "key": "vmRam",
      "label": "RAM asignada",
      "type": "number",
      "active": true,
      "required": false,
      "options": [],
      "unit": "",
      "hint": "",
      "maxLength": 500
    }
  },
  {
    "kind": "fields",
    "key": "vmDisk",
    "payload": {
      "key": "vmDisk",
      "label": "Disco virtual",
      "type": "text",
      "active": true,
      "required": false,
      "options": [],
      "unit": "",
      "hint": "",
      "maxLength": 500
    }
  },
  {
    "kind": "fields",
    "key": "containerImage",
    "payload": {
      "key": "containerImage",
      "label": "Imagen",
      "type": "text",
      "active": true,
      "required": false,
      "options": [],
      "unit": "",
      "hint": "",
      "maxLength": 500
    }
  },
  {
    "kind": "fields",
    "key": "containerHost",
    "payload": {
      "key": "containerHost",
      "label": "Host de contenedores",
      "type": "text",
      "active": true,
      "required": false,
      "options": [],
      "unit": "",
      "hint": "",
      "maxLength": 500
    }
  },
  {
    "kind": "fields",
    "key": "containerPorts",
    "payload": {
      "key": "containerPorts",
      "label": "Puertos publicados",
      "type": "text",
      "active": true,
      "required": false,
      "options": [],
      "unit": "",
      "hint": "",
      "maxLength": 500
    }
  },
  {
    "kind": "categories",
    "key": "computadoras",
    "payload": {
      "id": "computadoras",
      "label": "Computadoras",
      "prefix": "PC",
      "type": "Computadora",
      "icon": "monitor",
      "active": true,
      "fov": false,
      "tech": [
        "cpu",
        "ram",
        "storage",
        "os",
        "mac"
      ],
      "quick": [
        "name",
        "type",
        "brand",
        "model",
        "site",
        "locationId",
        "assigneeId",
        "ip"
      ],
      "advanced": [
        "serial",
        "cost",
        "statusId",
        "description"
      ],
      "transitions": null
    }
  },
  {
    "kind": "categories",
    "key": "notebooks",
    "payload": {
      "id": "notebooks",
      "label": "Notebooks",
      "prefix": "NB",
      "type": "Notebook",
      "icon": "laptop",
      "active": true,
      "fov": false,
      "tech": [
        "cpu",
        "ram",
        "storage",
        "os",
        "mac"
      ],
      "quick": [
        "name",
        "type",
        "brand",
        "model",
        "site",
        "locationId",
        "assigneeId",
        "ip"
      ],
      "advanced": [
        "serial",
        "cost",
        "statusId",
        "description"
      ],
      "transitions": null
    }
  },
  {
    "kind": "categories",
    "key": "servidores",
    "payload": {
      "id": "servidores",
      "label": "Servidores",
      "prefix": "SER",
      "type": "Servidor",
      "icon": "server",
      "active": true,
      "fov": false,
      "tech": [
        "cpu",
        "ram",
        "storage",
        "os",
        "mac",
        "rack"
      ],
      "quick": [
        "name",
        "type",
        "brand",
        "model",
        "site",
        "locationId",
        "assigneeId",
        "ip"
      ],
      "advanced": [
        "serial",
        "cost",
        "statusId",
        "description"
      ],
      "transitions": null
    }
  },
  {
    "kind": "categories",
    "key": "virtualizacion",
    "payload": {
      "id": "virtualizacion",
      "label": "Máquinas virtuales",
      "prefix": "VM",
      "type": "Máquina virtual",
      "icon": "server",
      "active": true,
      "fov": false,
      "tech": [
        "vmHost",
        "vmCpu",
        "vmRam",
        "vmDisk",
        "os"
      ],
      "quick": [
        "name",
        "type",
        "brand",
        "model",
        "site",
        "locationId",
        "assigneeId",
        "ip"
      ],
      "advanced": [
        "serial",
        "cost",
        "statusId",
        "description"
      ],
      "transitions": null
    }
  },
  {
    "kind": "categories",
    "key": "docker",
    "payload": {
      "id": "docker",
      "label": "Contenedores Docker",
      "prefix": "DCK",
      "type": "Docker",
      "icon": "box",
      "active": true,
      "fov": false,
      "tech": [
        "containerImage",
        "containerHost",
        "containerPorts"
      ],
      "quick": [
        "name",
        "type",
        "brand",
        "model",
        "site",
        "locationId",
        "assigneeId",
        "ip"
      ],
      "advanced": [
        "serial",
        "cost",
        "statusId",
        "description"
      ],
      "transitions": null
    }
  },
  {
    "kind": "categories",
    "key": "lxc",
    "payload": {
      "id": "lxc",
      "label": "Contenedores LXC",
      "prefix": "LXC",
      "type": "LXC",
      "icon": "box",
      "active": true,
      "fov": false,
      "tech": [
        "containerImage",
        "containerHost",
        "containerPorts"
      ],
      "quick": [
        "name",
        "type",
        "brand",
        "model",
        "site",
        "locationId",
        "assigneeId",
        "ip"
      ],
      "advanced": [
        "serial",
        "cost",
        "statusId",
        "description"
      ],
      "transitions": null
    }
  },
  {
    "kind": "categories",
    "key": "contenedores",
    "payload": {
      "id": "contenedores",
      "label": "Contenedores",
      "prefix": "CTR",
      "type": "Contenedor",
      "icon": "box",
      "active": true,
      "fov": false,
      "tech": [
        "containerImage",
        "containerHost",
        "containerPorts"
      ],
      "quick": [
        "name",
        "type",
        "brand",
        "model",
        "site",
        "locationId",
        "assigneeId",
        "ip"
      ],
      "advanced": [
        "serial",
        "cost",
        "statusId",
        "description"
      ],
      "transitions": null
    }
  },
  {
    "kind": "categories",
    "key": "switches",
    "payload": {
      "id": "switches",
      "label": "Switches",
      "prefix": "SW",
      "type": "Switch",
      "icon": "network",
      "active": true,
      "fov": false,
      "tech": [
        "ports",
        "firmware",
        "rack",
        "mac"
      ],
      "quick": [
        "name",
        "type",
        "brand",
        "model",
        "site",
        "locationId",
        "assigneeId",
        "ip"
      ],
      "advanced": [
        "serial",
        "cost",
        "statusId",
        "description"
      ],
      "transitions": null
    }
  },
  {
    "kind": "categories",
    "key": "routers",
    "payload": {
      "id": "routers",
      "label": "Routers",
      "prefix": "RTR",
      "type": "Router",
      "icon": "network",
      "active": true,
      "fov": false,
      "tech": [
        "ports",
        "firmware",
        "mac"
      ],
      "quick": [
        "name",
        "type",
        "brand",
        "model",
        "site",
        "locationId",
        "assigneeId",
        "ip"
      ],
      "advanced": [
        "serial",
        "cost",
        "statusId",
        "description"
      ],
      "transitions": null
    }
  },
  {
    "kind": "categories",
    "key": "impresoras",
    "payload": {
      "id": "impresoras",
      "label": "Impresoras",
      "prefix": "IMP",
      "type": "Impresora",
      "icon": "printer",
      "active": true,
      "fov": false,
      "tech": [
        "firmware",
        "mac",
        "ports"
      ],
      "quick": [
        "name",
        "type",
        "brand",
        "model",
        "site",
        "locationId",
        "assigneeId",
        "ip"
      ],
      "advanced": [
        "serial",
        "cost",
        "statusId",
        "description"
      ],
      "transitions": null
    }
  },
  {
    "kind": "categories",
    "key": "ups",
    "payload": {
      "id": "ups",
      "label": "UPS",
      "prefix": "UPS",
      "type": "UPS",
      "icon": "battery",
      "active": true,
      "fov": false,
      "tech": [
        "upsCapacity",
        "batteryLife",
        "rack"
      ],
      "quick": [
        "name",
        "type",
        "brand",
        "model",
        "site",
        "locationId",
        "assigneeId",
        "ip"
      ],
      "advanced": [
        "serial",
        "cost",
        "statusId",
        "description"
      ],
      "transitions": null
    }
  },
  {
    "kind": "categories",
    "key": "camaras",
    "payload": {
      "id": "camaras",
      "label": "Cámaras",
      "prefix": "CAM",
      "type": "Cámara IP",
      "icon": "camera",
      "active": true,
      "fov": true,
      "tech": [
        "resolution",
        "fovAngle",
        "nightVision",
        "poe"
      ],
      "quick": [
        "name",
        "type",
        "brand",
        "model",
        "site",
        "locationId",
        "assigneeId",
        "ip"
      ],
      "advanced": [
        "serial",
        "cost",
        "statusId",
        "description"
      ],
      "transitions": null
    }
  },
  {
    "kind": "categories",
    "key": "monitores",
    "payload": {
      "id": "monitores",
      "label": "Monitores",
      "prefix": "MON",
      "type": "Monitor",
      "icon": "monitor",
      "active": true,
      "fov": false,
      "tech": [
        "resolution"
      ],
      "quick": [
        "name",
        "type",
        "brand",
        "model",
        "site",
        "locationId",
        "assigneeId",
        "ip"
      ],
      "advanced": [
        "serial",
        "cost",
        "statusId",
        "description"
      ],
      "transitions": null
    }
  },
  {
    "kind": "categories",
    "key": "otros",
    "payload": {
      "id": "otros",
      "label": "Otros dispositivos",
      "prefix": "OTRO",
      "type": "Equipo",
      "icon": "box",
      "active": true,
      "fov": false,
      "tech": [],
      "quick": [
        "name",
        "type",
        "brand",
        "model",
        "site",
        "locationId",
        "assigneeId",
        "ip"
      ],
      "advanced": [
        "serial",
        "cost",
        "statusId",
        "description"
      ],
      "transitions": null
    }
  },
  {
    "kind": "statuses",
    "key": "in_use",
    "payload": {
      "id": "in_use",
      "label": "Asignado",
      "tone": "ok",
      "final": false,
      "active": true
    }
  },
  {
    "kind": "statuses",
    "key": "in_storage",
    "payload": {
      "id": "in_storage",
      "label": "En resguardo",
      "tone": "hold",
      "final": false,
      "active": true
    }
  },
  {
    "kind": "statuses",
    "key": "maintenance",
    "payload": {
      "id": "maintenance",
      "label": "Mantenimiento",
      "tone": "warn",
      "final": false,
      "active": true
    }
  },
  {
    "kind": "statuses",
    "key": "retired",
    "payload": {
      "id": "retired",
      "label": "Dado de baja",
      "tone": "down",
      "final": true,
      "active": true
    }
  },
  {
    "kind": "rules",
    "key": "identification",
    "payload": {
      "id": "identification",
      "separator": "-",
      "quickPad": 2,
      "siteCodeLength": 3,
      "includeSite": true,
      "order": "site-type",
      "siteCodes": {}
    }
  },
  {
    "kind": "rules",
    "key": "transitions",
    "payload": {
      "id": "transitions",
      "transitions": null
    }
  }
]"""


def upgrade() -> None:
    table = op.create_table(
        "inventory_catalog",
        sa.Column("kind", sa.String(16), primary_key=True),
        sa.Column("key", sa.String(64), primary_key=True),
        sa.Column("payload", sa.JSON(), nullable=False),
    )
    op.bulk_insert(table, json.loads(_SEED_JSON))


def downgrade() -> None:
    op.drop_table("inventory_catalog")
