"""Additive locale maps for admin-editable labels (S4/D9).

Relationship type labels live in ``String(80)`` columns, so the locale map needs
its own JSON columns; the legacy columns stay authoritative source text. The
inventory catalog already stores JSON and only gains a ``labels`` key.

Backfilling never invents a Spanish text: the ``es`` entry of a known id is
whatever the row already stores (or the immutable seed when it stores nothing),
so an edited installation keeps exactly what it showed. Only the English
caption of that same id is added, and an existing ``labels`` map is never
overwritten.
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "0041_i18n_labels"
down_revision = "0040_notification_i18n"
branch_labels = None
depends_on = None

#: Built-in captions: the stored Spanish text and its English counterpart.
_CATALOG_LABELS: dict[str, dict[str, tuple[str, str]]] = {
    "fields": {
        "serial": ("Número de serie", "Serial number"),
        "cpu": ("Procesador", "Processor"),
        "ram": ("Memoria RAM", "RAM"),
        "storage": ("Almacenamiento", "Storage"),
        "os": ("Sistema operativo", "Operating system"),
        "mac": ("Dirección MAC", "MAC address"),
        "firmware": ("Firmware", "Firmware"),
        "ports": ("Puertos", "Ports"),
        "rack": ("Rack / unidad", "Rack / unit"),
        "resolution": ("Resolución", "Resolution"),
        "fovAngle": ("Ángulo de visión", "Field of view"),
        "nightVision": ("Visión nocturna", "Night vision"),
        "poe": ("Alimentación PoE", "PoE power"),
        "upsCapacity": ("Capacidad", "Capacity"),
        "batteryLife": ("Autonomía", "Runtime"),
        "vmHost": ("Host", "Host"),
        "vmCpu": ("vCPU", "vCPU"),
        "vmRam": ("RAM asignada", "Assigned RAM"),
        "vmDisk": ("Disco virtual", "Virtual disk"),
        "containerImage": ("Imagen", "Image"),
        "containerHost": ("Host de contenedores", "Container host"),
        "containerPorts": ("Puertos publicados", "Published ports"),
    },
    "categories": {
        "computadoras": ("Computadoras", "Computers"),
        "notebooks": ("Notebooks", "Laptops"),
        "servidores": ("Servidores", "Servers"),
        "virtualizacion": ("Máquinas virtuales", "Virtual machines"),
        "docker": ("Contenedores Docker", "Docker containers"),
        "lxc": ("Contenedores LXC", "LXC containers"),
        "contenedores": ("Contenedores", "Containers"),
        "switches": ("Switches", "Switches"),
        "routers": ("Routers", "Routers"),
        "impresoras": ("Impresoras", "Printers"),
        "ups": ("UPS", "UPS"),
        "camaras": ("Cámaras", "Cameras"),
        "monitores": ("Monitores", "Monitors"),
        "otros": ("Otros dispositivos", "Other devices"),
    },
    "statuses": {
        "in_use": ("Asignado", "Assigned"),
        "in_storage": ("En resguardo", "In storage"),
        "maintenance": ("Mantenimiento", "Under maintenance"),
        "retired": ("Dado de baja", "Retired"),
    },
}

#: Seeded relationship types of migration ``0007_relationships``.
_RELATIONSHIP_LABELS: dict[str, tuple[str, str, str, str]] = {
    "connected_to": ("Conectado a", "Connected to", "Conectado desde", "Connected from"),
    "installed_in": ("Instalado en", "Installed in", "Contiene", "Contains"),
    "hosted_in": ("Alojado en", "Hosted in", "Aloja", "Hosts"),
    "protected_by": ("Protegido por", "Protected by", "Protege a", "Protects"),
    "depends_on": ("Depende de", "Depends on", "Requerido por", "Required by"),
    "associated_with": ("Asociado con", "Associated with", "Asociado con", "Associated with"),
}


def _relationship_types() -> sa.TableClause:
    return sa.table(
        "relationship_types",
        sa.column("key", sa.String(32)),
        sa.column("forward_label", sa.String(80)),
        sa.column("inverse_label", sa.String(80)),
        sa.column("forward_labels", sa.JSON()),
        sa.column("inverse_labels", sa.JSON()),
    )


def _catalog() -> sa.TableClause:
    return sa.table(
        "inventory_catalog",
        sa.column("kind", sa.String(16)),
        sa.column("key", sa.String(64)),
        sa.column("payload", sa.JSON()),
    )


def _backfill_relationship_types() -> None:
    table = _relationship_types()
    connection = op.get_bind()
    for row in connection.execute(sa.select(table)).mappings():
        expected = _RELATIONSHIP_LABELS.get(row["key"])
        if expected is None:
            continue
        forward_es, forward_en, inverse_es, inverse_en = expected
        if row["forward_labels"] is not None or row["inverse_labels"] is not None:
            continue
        connection.execute(
            table.update()
            .where(table.c.key == row["key"])
            .values(
                forward_labels={
                    "es": row["forward_label"] or forward_es,
                    "en": forward_en,
                },
                inverse_labels={
                    "es": row["inverse_label"] or inverse_es,
                    "en": inverse_en,
                },
            )
        )


def _backfill_catalog() -> None:
    table = _catalog()
    connection = op.get_bind()
    for row in connection.execute(sa.select(table)).mappings():
        expected = _CATALOG_LABELS.get(row["kind"], {}).get(row["key"])
        if expected is None:
            continue
        source, english = expected
        payload = dict(row["payload"] or {})
        if "labels" in payload:
            continue
        stored = payload.get("label")
        payload["labels"] = {
            "es": stored if isinstance(stored, str) and stored else source,
            "en": english,
        }
        connection.execute(
            table.update()
            .where(table.c.kind == row["kind"], table.c.key == row["key"])
            .values(payload=payload)
        )


def upgrade() -> None:
    op.add_column("relationship_types", sa.Column("forward_labels", sa.JSON(), nullable=True))
    op.add_column("relationship_types", sa.Column("inverse_labels", sa.JSON(), nullable=True))
    _backfill_relationship_types()
    _backfill_catalog()


def downgrade() -> None:
    # Label maps are additive data: the stored source text and the ids stay, so
    # dropping the columns cannot make an existing label unreadable.
    op.drop_column("relationship_types", "inverse_labels")
    op.drop_column("relationship_types", "forward_labels")
