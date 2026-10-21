"""Catalog migration preserves existing inventory records across an upgrade."""

from __future__ import annotations

from itsm.database import create_engine_from_settings
from itsm.identity.service import IdentityService
from itsm.inventory.service import InventoryService
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
        stored = InventoryService(session, settings).create(
            principal, {"name": "Before catalog", "quick_code": "LEGACY-01", "category": "Red"}
        )
    upgraded = run_migrations(settings)
    assert upgraded.returncode == 0, upgraded.stderr
    with Session(engine) as session:
        restored = InventoryService(session, settings).get(principal, stored.id)
        assert restored.as_payload() == stored.as_payload()
        from itsm.inventory.catalog import InventoryCatalog

        assert len(InventoryCatalog(session, settings).get(principal)["categories"]) == 14
    assert run_migrations(settings).returncode == 0
    engine.dispose()
