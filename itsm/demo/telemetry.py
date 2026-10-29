"""Explicit demo telemetry: a sanctioned Prometheus target for fictional assets.

The setup step is deliberately separate from demo initialization: creating the
dataset never configures monitoring. It refuses unmarked databases and existing
output paths, then uses the canonical services (login principal, inventory search,
monitoring configuration) so the written rows are the same rows an operator would
create through the API. Nothing here contacts a network target or a real device.
"""

from __future__ import annotations

import contextlib
import os
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import yaml
from sqlalchemy.engine import URL
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session

from itsm.config import Settings
from itsm.database import create_engine_from_settings, create_session_factory
from itsm.demo.state import DemoInstallation, is_demo
from itsm.identity.service import IdentityService
from itsm.inventory.service import MAX_LIMIT, InventoryService
from itsm.monitoring import rules
from itsm.monitoring.service import MonitoringService

DATASET = "fictional-infrastructure-v1"
CHECK_TYPE = "node"
MODULE = "node"
EXPORTER_NAME = "Demo node exporter"
LOOPBACK = "127.0.0.1"
DEFAULT_EXPORTER_PORT = 19101
NODE_METRICS = ("cpu", "memory", "disk", "temperature")
NODE_THRESHOLDS: dict[str, dict[str, float]] = {
    "cpu": {"warning": 80.0, "critical": 92.0},
    "memory": {"warning": 85.0, "critical": 95.0},
    "disk": {"warning": 85.0, "critical": 95.0},
    "temperature": {"warning": 60.0, "critical": 70.0},
}
SCRAPE_INTERVAL = "15s"


class DemoRefused(ValueError):
    """An explicit refusal: the command changed nothing."""


def refuse_production() -> None:
    """Refuse demo telemetry when the process claims a production environment."""
    if os.environ.get("ITSM_ENVIRONMENT", "development").lower() == "production":
        raise DemoRefused("demo telemetry is forbidden in production")


@contextlib.contextmanager
def demo_settings(directory: Path) -> Iterator[Settings]:
    """Ignore ambient ``ITSM_*`` configuration; the demo owns only its own database."""
    with contextlib.ExitStack() as restore:
        for key in tuple(os.environ):
            if key.startswith("ITSM_"):
                value = os.environ.pop(key)
                restore.callback(os.environ.__setitem__, key, value)
        database_url = URL.create("sqlite", database=str(directory / "demo.db")).render_as_string()
        yield Settings(_env_file=None, environment="development", database_url=database_url)


@contextlib.contextmanager
def demo_session(directory: Path) -> Iterator[tuple[Session, Settings]]:
    """Open a marked demo session, or refuse before touching anything."""
    directory = directory.absolute()
    if not (directory / "demo.db").is_file():
        raise DemoRefused("demo database does not exist")
    with demo_settings(directory) as settings:
        engine = create_engine_from_settings(settings)
        try:
            with create_session_factory(engine)() as session:
                try:
                    marked = is_demo(session)
                except SQLAlchemyError:
                    # An unmigrated file is not a demonstration installation either.
                    marked = False
                if not marked:
                    raise DemoRefused("demo database is not marked as a demonstration installation")
                yield session, settings
        finally:
            engine.dispose()


def demo_dataset(session: Session) -> str:
    """Return the persisted dataset label of the marked installation."""
    return (
        session.scalar(
            DemoInstallation.__table__.select().with_only_columns(DemoInstallation.dataset)
        )
        or DATASET
    )


def node_assets(inventory: InventoryService, principal: Any) -> list[Any]:
    """Assets whose category profile already resolves to node checks."""
    page = inventory.search(principal, limit=MAX_LIMIT)
    return [
        asset
        for asset in page.items
        if rules.default_profile(asset.category, asset.type).get("checkType") == CHECK_TYPE
    ]


def prometheus_config(exporter_port: int, asset_ids: list[str]) -> dict[str, Any]:
    """A standalone scrape file: no Alertmanager, no rule files, no discovery."""
    address = f"{LOOPBACK}:{exporter_port}"
    return {
        "global": {
            "scrape_interval": SCRAPE_INTERVAL,
            "scrape_timeout": "10s",
            "evaluation_interval": "60s",
        },
        "scrape_configs": [
            {
                "job_name": f"demo-node-{asset_id[:8]}",
                "metrics_path": f"/metrics/{asset_id}",
                "scheme": "http",
                "static_configs": [
                    {
                        "targets": [address],
                        "labels": {
                            "asset_id": asset_id,
                            "check_type": CHECK_TYPE,
                            "module": MODULE,
                            "dataset": DATASET,
                        },
                    }
                ],
            }
            for asset_id in asset_ids
        ],
    }


def render(config: dict[str, Any]) -> str:
    """Deterministic YAML text for the generated scrape configuration."""
    return yaml.safe_dump(config, sort_keys=False, allow_unicode=True)


def configure(
    directory: Path,
    username: str,
    password: str,
    output: Path | None,
    exporter_port: int,
) -> dict[str, Any]:
    """Configure the demo exporter and node checks; optionally write scrape YAML."""
    refuse_production()
    directory = directory.absolute()
    if output is not None and output.exists():
        raise DemoRefused("generated Prometheus configuration already exists")
    with demo_session(directory) as (session, settings):
        identity = IdentityService(session, settings)
        principal = identity.login(username, password).principal
        inventory = InventoryService(session, settings, identity=identity)
        assets = node_assets(inventory, principal)
        if not assets:
            raise DemoRefused("demo dataset has no assets configured for node monitoring")
        monitoring = MonitoringService(session, settings, identity=identity)
        address = f"{LOOPBACK}:{exporter_port}"
        exporter = monitoring.save_exporter(
            principal,
            {
                "name": EXPORTER_NAME,
                "kind": CHECK_TYPE,
                "module": MODULE,
                "address": address,
                "enabled": True,
            },
        )
        for asset in assets:
            monitoring.update_asset(
                principal,
                asset.id,
                {
                    "enabled": True,
                    "checkType": CHECK_TYPE,
                    "target": address,
                    "intervalSeconds": 30,
                    "minimumDurationSeconds": 60,
                    "metrics": list(NODE_METRICS),
                    "thresholds": NODE_THRESHOLDS,
                    "exporterId": exporter["id"],
                },
            )
        asset_ids = [asset.id for asset in assets]
        session.commit()
    payload = {
        "mode": "demo",
        "dataset": DATASET,
        "checkType": CHECK_TYPE,
        "exporterId": exporter["id"],
        "exporterAddress": address,
        "assetIds": asset_ids,
        "prometheusConfig": None,
    }
    if output is not None:
        try:
            output.write_text(render(prometheus_config(exporter_port, asset_ids)))
        except OSError:
            raise DemoRefused(
                "monitoring configuration was saved but the Prometheus file could not be "
                "written; choose a writable path and rerun"
            ) from None
        payload["prometheusConfig"] = str(output.absolute())
    return payload
