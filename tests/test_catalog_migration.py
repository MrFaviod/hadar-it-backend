"""Catalog migration preserves existing inventory records across an upgrade."""

from __future__ import annotations

from datetime import UTC, datetime
from uuid import uuid4

from itsm.database import create_engine_from_settings
from itsm.identity.service import IdentityService
from itsm.inventory.service import InventoryService
from sqlalchemy import text
from sqlalchemy.orm import Session
from tests.conftest import BACKEND_ROOT, bootstrap_admin, run_cli, run_migrations


def test_upgrade_installs_defaults_without_changing_existing_assets(settings_factory):
    settings = settings_factory()
    initial = run_cli(
        ["-m", "alembic", "-c", str(BACKEND_ROOT / "alembic.ini"), "upgrade", "0003_inventory"],
        settings,
    )
    assert initial.returncode == 0, initial.stderr
    bootstrap_admin(settings)
    engine = create_engine_from_settings(settings)
    with Session(engine) as session:
        identity = IdentityService(session, settings)
        principal = identity.resolve_actor(identity._identity_by_username("ana.admin").id)
        # Seed the historical schema directly: current services correctly require
        # current migrations and must not be run against an old schema.
        asset_id = str(uuid4())
        now = datetime.now(UTC)
        session.execute(
            text(
                "INSERT INTO assets (id, quick_code, quick_code_key, name, category, "
                "status, created_at, updated_at) VALUES (:id, 'LEGACY-01', 'legacy-01', "
                "'Before catalog', 'Red', 'in_use', :now, :now)"
            ),
            {"id": asset_id, "now": now},
        )
        session.commit()
    upgraded = run_migrations(settings)
    assert upgraded.returncode == 0, upgraded.stderr
    with Session(engine) as session:
        restored = InventoryService(session, settings).get(principal, asset_id)
        assert restored.id == asset_id
        assert restored.quick_code == "LEGACY-01"
        assert restored.name == "Before catalog"
        assert restored.category == "Red"
        assert restored.status == "in_use"
        assert restored.cost is None and restored.technical is None
        assert restored.images == {} and restored.archived is False
        from itsm.inventory.catalog import InventoryCatalog

        assert len(InventoryCatalog(session, settings).get(principal)["categories"]) == 14
    assert run_migrations(settings).returncode == 0
    engine.dispose()
