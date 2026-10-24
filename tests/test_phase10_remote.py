"""Built-in remote identifiers persist without bypassing technical catalog rules."""

from __future__ import annotations

import pytest
from itsm.identity.service import PermissionDenied, ValidationFailed
from itsm.inventory.service import InventoryService
from tests.inventory_support import asset_values, prepare


def test_remote_ids_persist_across_sessions_and_preserve_catalog_boundary(settings_factory):
    catalog = prepare(settings_factory)
    try:
        with catalog.session() as session:
            service = InventoryService(session, catalog.settings)
            asset = service.create(catalog.admin(), asset_values(category="routers"))
            service.update(
                catalog.admin(),
                asset.id,
                {"technical": {"anydeskId": "123456789", "rmmAgentId": "agent-10"}},
            )
        with catalog.session() as session:
            service = InventoryService(session, catalog.settings)
            saved = service.get(catalog.admin(), asset.id)
            assert saved.technical == {"anydeskId": "123456789", "rmmAgentId": "agent-10"}
            with pytest.raises(ValidationFailed):
                service.update(
                    catalog.admin(), asset.id, {"technical": {"unregistered": "not allowed"}}
                )
            with pytest.raises(ValidationFailed):
                service.update(catalog.admin(), asset.id, {"technical": {"anydeskId": "bad/id"}})
        reader = catalog.add_user("remote.reader", "Remote reader", "reader")
        with catalog.session() as session, pytest.raises(PermissionDenied):
            InventoryService(session, catalog.settings).update(
                reader, asset.id, {"technical": {"anydeskId": "987654321"}}
            )
        with catalog.session() as session:
            saved = InventoryService(session, catalog.settings).get(catalog.admin(), asset.id)
            assert saved.technical["anydeskId"] == "123456789"
    finally:
        catalog.engine.dispose()
