"""Installation metadata matching the existing inventory form vocabulary."""

from __future__ import annotations

from typing import Any

COMMON_KEYS = (
    "name",
    "category",
    "type",
    "brand",
    "model",
    "serial",
    "ip",
    "site",
    "locationId",
    "assigneeId",
    "cost",
    "statusId",
    "image",
    "description",
)
FIELD_TYPES = frozenset({"text", "textarea", "number", "date", "select", "boolean", "url"})


def installation_catalog() -> dict[str, list[dict[str, Any]]]:
    """Return fresh defaults, never accounts or inventory records."""
    field_specs = [
        ("serial", "Número de serie", "text"),
        ("cpu", "Procesador", "text"),
        ("ram", "Memoria RAM", "number"),
        ("storage", "Almacenamiento", "text"),
        ("os", "Sistema operativo", "text"),
        ("mac", "Dirección MAC", "text"),
        ("firmware", "Firmware", "text"),
        ("ports", "Puertos", "number"),
        ("rack", "Rack / unidad", "text"),
        ("resolution", "Resolución", "text"),
        ("fovAngle", "Ángulo de visión", "text"),
        ("nightVision", "Visión nocturna", "boolean"),
        ("poe", "Alimentación PoE", "boolean"),
        ("upsCapacity", "Capacidad", "text"),
        ("batteryLife", "Autonomía", "text"),
        ("vmHost", "Host", "text"),
        ("vmCpu", "vCPU", "number"),
        ("vmRam", "RAM asignada", "number"),
        ("vmDisk", "Disco virtual", "text"),
        ("containerImage", "Imagen", "text"),
        ("containerHost", "Host de contenedores", "text"),
        ("containerPorts", "Puertos publicados", "text"),
    ]
    fields = [
        dict(
            key=k,
            label=label,
            type=kind,
            active=True,
            required=False,
            options=[],
            unit="",
            hint="",
            maxLength=500,
        )
        for k, label, kind in field_specs
    ]
    computer = ["cpu", "ram", "storage", "os", "mac"]
    container = ["containerImage", "containerHost", "containerPorts"]
    category_specs = [
        ("computadoras", "Computadoras", "PC", "Computadora", "monitor", computer),
        ("notebooks", "Notebooks", "NB", "Notebook", "laptop", computer),
        ("servidores", "Servidores", "SER", "Servidor", "server", [*computer, "rack"]),
        (
            "virtualizacion",
            "Máquinas virtuales",
            "VM",
            "Máquina virtual",
            "server",
            ["vmHost", "vmCpu", "vmRam", "vmDisk", "os"],
        ),
        ("docker", "Contenedores Docker", "DCK", "Docker", "box", container),
        ("lxc", "Contenedores LXC", "LXC", "LXC", "box", container),
        ("contenedores", "Contenedores", "CTR", "Contenedor", "box", container),
        ("switches", "Switches", "SW", "Switch", "network", ["ports", "firmware", "rack", "mac"]),
        ("routers", "Routers", "RTR", "Router", "network", ["ports", "firmware", "mac"]),
        ("impresoras", "Impresoras", "IMP", "Impresora", "printer", ["firmware", "mac", "ports"]),
        ("ups", "UPS", "UPS", "UPS", "battery", ["upsCapacity", "batteryLife", "rack"]),
        (
            "camaras",
            "Cámaras",
            "CAM",
            "Cámara IP",
            "camera",
            ["resolution", "fovAngle", "nightVision", "poe"],
        ),
        ("monitores", "Monitores", "MON", "Monitor", "monitor", ["resolution"]),
        ("otros", "Otros dispositivos", "OTRO", "Equipo", "box", []),
    ]
    categories = [
        dict(
            id=k,
            label=label,
            prefix=prefix,
            type=kind,
            icon=icon,
            active=True,
            fov=k == "camaras",
            tech=list(tech),
            quick=["name", "type", "brand", "model", "site", "locationId", "assigneeId", "ip"],
            advanced=["serial", "cost", "statusId", "description"],
            transitions=None,
        )
        for k, label, prefix, kind, icon, tech in category_specs
    ]
    statuses = [
        dict(id=k, label=label, tone=tone, final=final, active=True)
        for k, label, tone, final in [
            ("in_use", "Asignado", "ok", False),
            ("in_storage", "En resguardo", "hold", False),
            ("maintenance", "Mantenimiento", "warn", False),
            ("retired", "Dado de baja", "down", True),
        ]
    ]
    return dict(
        fields=fields,
        categories=categories,
        statuses=statuses,
        rules=[
            dict(
                id="identification",
                separator="-",
                quickPad=2,
                siteCodeLength=3,
                includeSite=True,
                order="site-type",
                siteCodes={},
            ),
            dict(id="transitions", transitions=None),
        ],
    )
