"""Inventory service: shared validation, authorization, SQL search and audit."""

from __future__ import annotations

from collections.abc import Callable

import pytest
from itsm.config import Settings
from itsm.identity.service import NotFound, PermissionDenied, ValidationFailed
from itsm.inventory.service import InventoryService
from sqlalchemy.orm import Session
from tests.inventory_support import OPERATOR, READER, Catalog, asset_values, prepare

SettingsFactory = Callable[..., Settings]


@pytest.fixture
def catalog(settings_factory: SettingsFactory) -> Catalog:
    return prepare(settings_factory)


def service(catalog: Catalog, session: Session) -> InventoryService:
    return InventoryService(session, catalog.settings)


def test_create_assigns_permanent_uuid_and_generated_quick_code(catalog: Catalog) -> None:
    with catalog.session() as session:
        created = service(catalog, session).create(
            catalog.admin(), asset_values(quick_code=None, name="Notebook Dell 5420")
        )
    assert len(created.id) == 36
    assert created.id.count("-") == 4
    assert created.quick_code.startswith("A-")
    assert len(created.quick_code) == 10
    assert created.name == "Notebook Dell 5420"


def test_create_preserves_explicit_quick_code_and_status(catalog: Catalog) -> None:
    with catalog.session() as session:
        created = service(catalog, session).create(
            catalog.admin(), asset_values(quick_code="sw-sn-001", status="in_storage")
        )
    assert created.quick_code == "sw-sn-001"
    assert created.status == "in_storage"
    assert created.site == "Sede Norte"


def test_quick_code_collision_is_case_insensitive_and_advances_the_suffix(
    catalog: Catalog,
) -> None:
    with catalog.session() as session:
        first = service(catalog, session).create(
            catalog.admin(), asset_values(quick_code="SW-SN-001")
        )

    with catalog.session() as session:
        second = service(catalog, session).create(
            catalog.admin(), asset_values(quick_code="sw-sn-001")
        )

    assert second.quick_code == "sw-sn-002"
    assert second.id != first.id
    assert catalog.asset_count() == 2


def test_update_changes_quick_code_and_keeps_the_same_id(catalog: Catalog) -> None:
    with catalog.session() as session:
        created = service(catalog, session).create(catalog.admin(), asset_values())

    with catalog.session() as session:
        updated = service(catalog, session).update(
            catalog.admin(), created.id, {"quick_code": "SW-SN-999", "responsible": "Soporte"}
        )
        repeated = service(catalog, session).update(
            catalog.admin(), created.id, {"quick_code": "SW-SN-999"}
        )

    assert updated.id == created.id == repeated.id
    assert updated.quick_code == "SW-SN-999"
    assert updated.responsible == "Soporte"


def test_update_cannot_replace_the_asset_id(catalog: Catalog) -> None:
    with catalog.session() as session:
        created = service(catalog, session).create(catalog.admin(), asset_values())

    with pytest.raises(ValidationFailed), catalog.session() as session:
        service(catalog, session).update(catalog.admin(), created.id, {"id": "other-id"})

    with catalog.session() as session:
        stored = service(catalog, session).get(catalog.admin(), created.id)
    assert stored.id == created.id


def test_unknown_asset_is_not_found(catalog: Catalog) -> None:
    with catalog.session() as session, pytest.raises(NotFound):
        service(catalog, session).get(catalog.admin(), "00000000-0000-0000-0000-000000000000")


def test_invalid_values_are_rejected_before_any_write(catalog: Catalog) -> None:
    invalid = [
        asset_values(name=""),
        asset_values(name="x" * 161),
        asset_values(status="deleted"),
        asset_values(quick_code=""),
        asset_values(serial="x" * 81),
        asset_values(unknown_field="value"),
    ]
    for values in invalid:
        with pytest.raises(ValidationFailed), catalog.session() as session:
            service(catalog, session).create(catalog.admin(), values)

    assert catalog.asset_count() == 0


def test_reader_can_search_but_cannot_create(catalog: Catalog) -> None:
    catalog.add_user(*READER)
    reader = catalog.principal(READER[0])

    with catalog.session() as session:
        service(catalog, session).create(catalog.admin(), asset_values())

    with catalog.session() as session:
        page = service(catalog, session).search(reader, query="Aruba")
    assert page.total == 1
    assert page.items[0].quick_code == "SW-SN-001"

    with pytest.raises(PermissionDenied), catalog.session() as session:
        service(catalog, session).create(reader, asset_values(quick_code="SW-SN-002"))

    assert catalog.asset_count() == 1


def test_responsible_changes_require_the_assign_permission(catalog: Catalog) -> None:
    with catalog.session() as session:
        identity = catalog.service(session)
        role = identity.create_role(
            catalog.admin(),
            name="inventario-editor",
            permissions=["assets.view", "assets.edit"],
        )
    catalog.add_user("editor-user", "Editor User", role.id)
    editor = catalog.principal("editor-user")

    with catalog.session() as session:
        created = service(catalog, session).create(
            catalog.admin(), asset_values(responsible="Matriz NOC")
        )

    with catalog.session() as session:
        updated = service(catalog, session).update(editor, created.id, {"location": "Rack 3"})
    assert updated.location == "Rack 3"

    with pytest.raises(PermissionDenied), catalog.session() as session:
        service(catalog, session).update(editor, created.id, {"responsible": "Otro"})

    with catalog.session() as session:
        stored = service(catalog, session).get(catalog.admin(), created.id)
    assert stored.responsible == "Matriz NOC"

    with pytest.raises(PermissionDenied), catalog.session() as session:
        service(catalog, session).create(
            editor, asset_values(quick_code="SW-SN-002", responsible="Otro")
        )


def test_batch_create_advances_a_colliding_numeric_suffix(catalog: Catalog) -> None:
    with catalog.session() as session:
        service(catalog, session).create(catalog.admin(), asset_values(quick_code="DUP-1"))

    with catalog.session() as session:
        result = service(catalog, session).batch(
            catalog.admin(),
            create=[
                asset_values(quick_code="NEW-1"),
                asset_values(quick_code="dup-1"),
            ],
        )

    assert [view.quick_code for view in result.created] == ["NEW-1", "dup-2"]
    assert catalog.asset_count() == 3


def test_batch_create_requires_assign_for_a_responsible(catalog: Catalog) -> None:
    with catalog.session() as session:
        identity = catalog.service(session)
        role = identity.create_role(
            catalog.admin(),
            name="inventario-batch-editor",
            permissions=["assets.view", "assets.edit"],
        )
    catalog.add_user("batch-editor", "Batch Editor", role.id)
    editor = catalog.principal("batch-editor")

    with pytest.raises(PermissionDenied), catalog.session() as session:
        service(catalog, session).batch(
            editor,
            create=[asset_values(quick_code="NO-ASSIGN-1", responsible="Matriz NOC")],
        )

    assert catalog.asset_count() == 0
    denied = [event for event in catalog.audit("assets.assign") if event["outcome"] == "denied"]
    assert denied and denied[0]["actor"] == "batch-editor"

    with catalog.session() as session:
        without_responsible = service(catalog, session).batch(
            editor, create=[asset_values(quick_code="NO-ASSIGN-2", responsible=None)]
        )
    assert [view.responsible for view in without_responsible.created] == [None]
    assert catalog.asset_count() == 1

    with catalog.session() as session:
        assigned = service(catalog, session).batch(
            catalog.admin(),
            create=[asset_values(quick_code="ASSIGN-1", responsible="Matriz NOC")],
        )
    assert assigned.created[0].responsible == "Matriz NOC"
    assert catalog.asset_count() == 2


def test_batch_update_is_atomic_on_unknown_asset(catalog: Catalog) -> None:
    with catalog.session() as session:
        first = service(catalog, session).create(catalog.admin(), asset_values(quick_code="K-1"))
        second = service(catalog, session).create(
            catalog.admin(), asset_values(quick_code="K-2", name="Segundo activo")
        )

    with pytest.raises(NotFound), catalog.session() as session:
        service(catalog, session).batch(
            catalog.admin(),
            update=[
                {"id": first.id, "name": "Renombrado"},
                {"id": "00000000-0000-0000-0000-000000000000", "name": "Fantasma"},
            ],
        )

    with catalog.session() as session:
        stored = service(catalog, session).get(catalog.admin(), first.id)
        untouched = service(catalog, session).get(catalog.admin(), second.id)
    assert stored.name == "Switch Aruba 2930F"
    assert untouched.name == "Segundo activo"


def test_batch_respects_the_bounded_operation_count(catalog: Catalog) -> None:
    with pytest.raises(ValidationFailed), catalog.session() as session:
        service(catalog, session).batch(
            catalog.admin(),
            create=[asset_values(quick_code=f"B-{index}") for index in range(51)],
        )

    assert catalog.asset_count() == 0


def test_search_filters_paginates_and_escapes_wildcards(catalog: Catalog) -> None:
    with catalog.session() as session:
        inventory = service(catalog, session)
        inventory.create(
            catalog.admin(),
            asset_values(quick_code="NET-1", name="Switch 100% backup", site="Sede Norte"),
        )
        inventory.create(
            catalog.admin(),
            asset_values(
                quick_code="NET-2",
                name="Router borde",
                site="Asuncion",
                category="Red",
                status="maintenance",
            ),
        )
        inventory.create(
            catalog.admin(),
            asset_values(
                quick_code="PC-1",
                name="Notebook Dell",
                site="Sede Norte",
                category="Computo",
                status="in_use",
            ),
        )

    with catalog.session() as session:
        inventory = service(catalog, session)
        assert inventory.search(catalog.admin(), query="100%").total == 1
        assert inventory.search(catalog.admin(), query="%").total == 1
        assert inventory.search(catalog.admin(), query="_").total == 0
        assert inventory.search(catalog.admin(), query="' OR 1=1 --").total == 0
        assert inventory.search(catalog.admin(), category="red").total == 2
        assert inventory.search(catalog.admin(), site="Sede Norte").total == 2
        assert inventory.search(catalog.admin(), status="maintenance").total == 1
        page = inventory.search(catalog.admin(), site="Sede Norte", limit=1, offset=1)
    assert page.total == 2
    assert len(page.items) == 1
    assert page.limit == 1
    assert page.offset == 1


@pytest.mark.parametrize("case", ["missing", "purged", "malformed"])
def test_search_missing_or_purged_asset_returns_empty_page(catalog: Catalog, case: str) -> None:
    asset_id = "not-a-uuid" if case == "malformed" else "00000000-0000-0000-0000-000000000000"
    with catalog.session() as session:
        inventory = service(catalog, session)
        inventory.create(catalog.admin(), asset_values(quick_code="OTHER-001"))
        if case == "purged":
            created = inventory.create(catalog.admin(), asset_values())
            asset_id = created.id
            found = inventory.search(catalog.admin(), asset_id=asset_id)
            assert [item.id for item in found.items] == [asset_id]
            inventory.purge(catalog.admin(), asset_id, confirm=True)
        page = inventory.search(catalog.admin(), asset_id=asset_id, limit=7, offset=3)
        assert page.as_payload() == {"items": [], "total": 0, "limit": 7, "offset": 3}
        if case != "malformed":
            with pytest.raises(NotFound):
                inventory.get(catalog.admin(), asset_id)


def test_missing_asset_search_still_requires_global_view_permission(catalog: Catalog) -> None:
    with catalog.session() as session:
        role = catalog.service(session).create_role(
            catalog.admin(), name="no-inventory-read", permissions=[]
        )
    actor = catalog.add_user("no-read-user", "No Read User", role.id)
    with catalog.session() as session, pytest.raises(PermissionDenied):
        service(catalog, session).search(actor, asset_id="00000000-0000-0000-0000-000000000000")


def test_search_bounds_are_validated(catalog: Catalog) -> None:
    with catalog.session() as session:
        inventory = service(catalog, session)
        for limit in (0, 201):
            with pytest.raises(ValidationFailed):
                inventory.search(catalog.admin(), limit=limit)
        with pytest.raises(ValidationFailed):
            inventory.search(catalog.admin(), offset=-1)
        with pytest.raises(ValidationFailed):
            inventory.search(catalog.admin(), status="deleted")
        with pytest.raises(ValidationFailed, match="asset id is required"):
            inventory.search(catalog.admin(), asset_id=7)  # type: ignore[arg-type]


def test_allowed_and_denied_operations_are_audited(catalog: Catalog) -> None:
    catalog.add_user(*OPERATOR)
    operator = catalog.principal(OPERATOR[0])
    catalog.add_user(*READER)
    reader = catalog.principal(READER[0])

    with catalog.session() as session:
        service(catalog, session).create(operator, asset_values())

    with pytest.raises(PermissionDenied), catalog.session() as session:
        service(catalog, session).create(reader, asset_values(quick_code="DENIED-1"))

    actions = {event["action"] for event in catalog.audit()}
    assert "inventory.asset_created" in actions
    assert "assets.edit" in actions
    denied = [event for event in catalog.audit() if event["outcome"] == "denied"]
    assert denied and denied[-1]["actor"] == READER[0]
    assert catalog.asset_count() == 1
