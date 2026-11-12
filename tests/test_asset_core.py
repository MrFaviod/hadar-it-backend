"""Asset core: common fields, clone, lifecycle, immutable history and purge guards."""

from __future__ import annotations

from collections.abc import Callable, Iterator
from contextlib import contextmanager
from typing import Any

import pytest
from itsm.config import Settings
from itsm.identity.service import Conflict, NotFound, PermissionDenied, ValidationFailed
from itsm.inventory.service import InventoryService
from sqlalchemy import text
from sqlalchemy.orm import Session
from tests.conftest import ADMIN_USERNAME
from tests.inventory_support import OPERATOR, Catalog, asset_values, prepare

SettingsFactory = Callable[..., Settings]

EDIT_ONLY_PERMISSIONS = ["assets.view", "assets.edit"]


@pytest.fixture
def catalog(settings_factory: SettingsFactory) -> Catalog:
    return prepare(settings_factory)


def service(catalog: Catalog, session: Session) -> InventoryService:
    return InventoryService(session, catalog.settings)


@contextmanager
def inventory(catalog: Catalog) -> Iterator[InventoryService]:
    """One request-scoped service bound to a fresh session."""
    with catalog.session() as session:
        yield service(catalog, session)


@contextmanager
def edit_only_principal(catalog: Catalog, username: str = "editor-user") -> Iterator[Any]:
    """An identity allowed to edit assets but neither assign nor purge."""
    with catalog.session() as session:
        role = catalog.service(session).create_role(
            catalog.admin(),
            name=f"inventario-campos-{username}",
            permissions=EDIT_ONLY_PERMISSIONS,
        )
    yield catalog.add_user(username, "Editor User", role.id)


def scalar(catalog: Catalog, statement: str, **params: Any) -> Any:
    with catalog.engine.connect() as connection:
        return connection.execute(text(statement), params).scalar_one()


def rows(catalog: Catalog, statement: str, **params: Any) -> list[Any]:
    with catalog.engine.connect() as connection:
        return list(connection.execute(text(statement), params).all())


def history(catalog: Catalog, asset_id: str) -> list[Any]:
    """History entries as the canonical service returns them, oldest first."""
    with inventory(catalog) as assets:
        return list(assets.history(catalog.admin(), asset_id).items)


def create(catalog: Catalog, **overrides: Any) -> Any:
    with inventory(catalog) as assets:
        return assets.create(catalog.admin(), asset_values(**overrides))


# --------------------------------------------------------------- common fields
def test_sparse_asset_is_created_without_any_optional_field(catalog: Catalog) -> None:
    with inventory(catalog) as assets:
        created = assets.create(catalog.admin(), {"name": "Activo sin datos"})

    assert created.cost is None
    assert created.technical is None
    assert created.archived is False
    assert created.archived_at is None
    assert created.images == {}
    assert created.quick_code.startswith("A-")
    assert created.status == "in_use"
    assert created.as_payload()["cost"] is None
    assert created.as_payload()["technical"] is None


def test_cost_and_technical_values_round_trip_and_clear(catalog: Catalog) -> None:
    with inventory(catalog) as assets:
        created = assets.create(
            catalog.admin(),
            asset_values(
                cost=1250.5,
                technical={"ramGb": 16, "hasWifi": True, "os": "Fedora 44"},
            ),
        )
    payload = created.as_payload()
    assert payload["cost"] == "1250.50"
    assert payload["technical"] == {"ramGb": 16, "hasWifi": True, "os": "Fedora 44"}

    with inventory(catalog) as assets:
        updated = assets.update(
            catalog.admin(), created.id, {"cost": "0", "technical": {"ramGb": 32}}
        )
    assert updated.as_payload()["cost"] == "0.00"
    assert updated.technical == {"ramGb": 32}

    with inventory(catalog) as assets:
        cleared = assets.update(catalog.admin(), created.id, {"cost": None, "technical": None})
    assert cleared.cost is None
    assert cleared.technical is None


@pytest.mark.parametrize(
    "cost",
    [-1, "-0.01", "12.345", "not-a-number", 1_000_000_001, True, float("nan")],
)
def test_invalid_cost_is_rejected_without_writing(catalog: Catalog, cost: Any) -> None:
    with pytest.raises(ValidationFailed), inventory(catalog) as assets:
        assets.create(catalog.admin(), asset_values(cost=cost))

    assert catalog.asset_count() == 0


@pytest.mark.parametrize("ip", ["999.1.1.1", "not-an-ip", "192.168.1.1/24", "http://x", "1.2.3"])
def test_invalid_ip_is_rejected_without_writing(catalog: Catalog, ip: str) -> None:
    with pytest.raises(ValidationFailed), inventory(catalog) as assets:
        assets.create(catalog.admin(), asset_values(ip=ip))

    assert catalog.asset_count() == 0


def test_valid_ipv6_and_ipv4_addresses_are_accepted(catalog: Catalog) -> None:
    with inventory(catalog) as assets:
        ipv6 = assets.create(catalog.admin(), asset_values(quick_code="IP-6", ip="2001:db8::1"))
        ipv4 = assets.create(catalog.admin(), asset_values(quick_code="IP-4", ip="10.0.0.7"))

    assert ipv6.ip == "2001:db8::1"
    assert ipv4.ip == "10.0.0.7"


@pytest.mark.parametrize(
    "technical",
    [
        {"nested": {"a": 1}},
        {"list": [1, [2]]},
        {f"key{index}": index for index in range(41)},
        {"os": "x" * 501},
        {"bad key!": 1},
        {"n": 10**13},
        {"n": float("inf")},
        {"ok": object()},
    ],
)
def test_technical_values_are_typed_and_bounded(catalog: Catalog, technical: Any) -> None:
    with pytest.raises(ValidationFailed), inventory(catalog) as assets:
        assets.create(catalog.admin(), asset_values(technical=technical))

    assert catalog.asset_count() == 0


# -------------------------------------------------------------------- duplicado
def test_clone_creates_a_new_permanent_id_and_copies_common_values(catalog: Catalog) -> None:
    created = create(
        catalog,
        quick_code="CLONE-SRC",
        status="maintenance",
        responsible="Matriz NOC",
        cost=99.9,
        technical={"ramGb": 8},
    )

    with inventory(catalog) as assets:
        clone = assets.clone(catalog.admin(), created.id)

    assert clone.id != created.id
    assert clone.quick_code.startswith("A-")
    assert clone.name == created.name
    assert clone.status == "maintenance"
    assert clone.responsible == "Matriz NOC"
    assert clone.location == created.location
    assert clone.cost == created.cost
    assert clone.technical == {"ramGb": 8}
    assert clone.archived is False
    assert clone.images == {}
    assert catalog.asset_count() == 2
    assert [entry.action for entry in history(catalog, clone.id)] == ["cloned"]
    assert [entry.action for entry in history(catalog, created.id)] == ["created"]


def test_clone_accepts_an_explicit_quick_code_and_rejects_a_taken_one(
    catalog: Catalog,
) -> None:
    first = create(catalog, quick_code="DUP-SRC")
    second = create(catalog, quick_code="DUP-TAKEN")

    with inventory(catalog) as assets:
        clone = assets.clone(catalog.admin(), first.id, {"quick_code": "CLONE-9"})
        advanced = assets.clone(catalog.admin(), first.id, {"quick_code": "clone-9"})
    assert clone.quick_code == "CLONE-9"
    assert advanced.quick_code == "clone-10"
    assert advanced.id != clone.id

    with pytest.raises(Conflict), inventory(catalog) as assets:
        assets.clone(catalog.admin(), second.id, {"quick_code": "dup-taken"})

    assert catalog.asset_count() == 4


def test_clone_requires_assign_when_it_copies_a_responsible(catalog: Catalog) -> None:
    created = create(catalog, quick_code="CLONE-ASSIGN", responsible="Matriz NOC")
    create(catalog, quick_code="CLONE-FREE", responsible=None)

    with edit_only_principal(catalog) as editor:
        with pytest.raises(PermissionDenied), inventory(catalog) as assets:
            assets.clone(editor, created.id)

        free = rows(catalog, "SELECT id FROM assets WHERE quick_code = 'CLONE-FREE'")[0][0]
        with inventory(catalog) as assets:
            clone = assets.clone(editor, free)

    assert clone.responsible is None
    assert catalog.asset_count() == 3


def test_clone_of_an_archived_asset_is_not_archived(catalog: Catalog) -> None:
    created = create(catalog, quick_code="CLONE-ARCH")
    with inventory(catalog) as assets:
        assets.archive(catalog.admin(), created.id, reason="guardado")
        clone = assets.clone(catalog.admin(), created.id)

    assert clone.archived is False
    with inventory(catalog) as assets:
        assert assets.get(catalog.admin(), created.id).archived is True


# ------------------------------------------------------- archivado y restauración
def test_archive_keeps_status_assignment_and_location_and_restore_clears_it(
    catalog: Catalog,
) -> None:
    created = create(
        catalog,
        quick_code="ARCH-1",
        status="maintenance",
        responsible="Matriz NOC",
        location="Rack 2",
    )

    with inventory(catalog) as assets:
        archived = assets.archive(catalog.admin(), created.id, reason="fin de vida")
    assert archived.archived is True
    assert archived.archived_at is not None
    assert archived.status == "maintenance"
    assert archived.responsible == "Matriz NOC"
    assert archived.location == "Rack 2"
    assert archived.site == "Sede Norte"

    with inventory(catalog) as assets:
        assert assets.search(catalog.admin(), archived=False).total == 0
        assert assets.search(catalog.admin(), archived=True).total == 1
        assert assets.search(catalog.admin()).total == 1
        assert assets.get(catalog.admin(), created.id).responsible == "Matriz NOC"

    with inventory(catalog) as assets:
        restored = assets.restore(catalog.admin(), created.id)
    assert restored.archived is False
    assert restored.archived_at is None
    assert restored.status == "maintenance"
    assert restored.responsible == "Matriz NOC"
    assert restored.location == "Rack 2"
    assert [entry.action for entry in history(catalog, created.id)] == [
        "created",
        "archived",
        "restored",
    ]
    archived_row = history(catalog, created.id)[1]
    assert archived_row.archived_old is False and archived_row.archived_new is True
    assert archived_row.reason == "fin de vida"


def test_archive_and_restore_reject_an_inconsistent_lifecycle(catalog: Catalog) -> None:
    created = create(catalog, quick_code="ARCH-2")

    with pytest.raises(Conflict), inventory(catalog) as assets:
        assets.restore(catalog.admin(), created.id)

    with inventory(catalog) as assets:
        assets.archive(catalog.admin(), created.id)

    with pytest.raises(Conflict), inventory(catalog) as assets:
        assets.archive(catalog.admin(), created.id)


def test_archived_asset_organization_is_frozen_for_update_and_batch(catalog: Catalog) -> None:
    created = create(catalog, quick_code="ARCH-4", location="Rack 2")
    with inventory(catalog) as assets:
        assets.archive(catalog.admin(), created.id)

    with pytest.raises(Conflict), inventory(catalog) as assets:
        assets.update(catalog.admin(), created.id, {"location": "Rack 3"})
    with pytest.raises(Conflict), inventory(catalog) as assets:
        assets.batch(catalog.admin(), update=[{"id": created.id, "location": "Rack 3"}])

    with inventory(catalog) as assets:
        assert assets.get(catalog.admin(), created.id).location == "Rack 2"
        renamed = assets.update(catalog.admin(), created.id, {"name": "Renombrado"})
    assert renamed.name == "Renombrado"


def test_archiving_does_not_require_the_assign_permission(catalog: Catalog) -> None:
    created = create(catalog, quick_code="ARCH-3", responsible="Matriz NOC")

    with edit_only_principal(catalog) as editor:
        with inventory(catalog) as assets:
            archived = assets.archive(editor, created.id)
        with inventory(catalog) as assets:
            restored = assets.restore(editor, created.id)

    assert archived.responsible == "Matriz NOC"
    assert restored.responsible == "Matriz NOC"


def test_retire_requires_a_reason_and_clears_the_responsible(catalog: Catalog) -> None:
    created = create(catalog, quick_code="RET-1", responsible="Matriz NOC")

    for reason in ("", "abc"):
        with pytest.raises(ValidationFailed), inventory(catalog) as assets:
            assets.retire(catalog.admin(), created.id, reason=reason)

    with inventory(catalog) as assets:
        assert assets.get(catalog.admin(), created.id).responsible == "Matriz NOC"
        retired = assets.retire(catalog.admin(), created.id, reason="Baja por fin de vida")

    assert retired.status == "retired"
    assert retired.responsible is None
    assert retired.location == created.location
    assert retired.archived is False
    retired_row = history(catalog, created.id)[-1]
    assert retired_row.action == "retired"
    assert retired_row.status_old == "in_use" and retired_row.status_new == "retired"
    assert retired_row.reason == "Baja por fin de vida"

    with pytest.raises(Conflict), inventory(catalog) as assets:
        assets.retire(catalog.admin(), created.id, reason="Otra baja")


def test_retire_requires_assign_because_it_clears_the_responsible(catalog: Catalog) -> None:
    created = create(catalog, quick_code="RET-2", responsible="Matriz NOC")

    with edit_only_principal(catalog) as editor:
        with pytest.raises(PermissionDenied), inventory(catalog) as assets:
            assets.retire(editor, created.id, reason="Baja sin permiso")

        with inventory(catalog) as assets:
            stored = assets.get(editor, created.id)

    assert stored.status == "in_use"
    assert stored.responsible == "Matriz NOC"


# ------------------------------------------------------------------- historial
def test_history_captures_old_new_code_lifecycle_actor_and_time(catalog: Catalog) -> None:
    created = create(catalog, quick_code="HIS-1", status="in_use")

    with inventory(catalog) as assets:
        assets.update(catalog.admin(), created.id, {"quick_code": "HIS-2", "status": "maintenance"})
        assets.archive(catalog.admin(), created.id, reason="guardado")

    entries = history(catalog, created.id)
    assert [entry.action for entry in entries] == ["created", "updated", "archived"]

    updated = entries[1]
    assert updated.quick_code_old == "HIS-1" and updated.quick_code_new == "HIS-2"
    assert updated.status_old == "in_use" and updated.status_new == "maintenance"
    assert updated.archived_old is False and updated.archived_new is False
    assert updated.actor_username == ADMIN_USERNAME
    assert updated.created_at is not None
    assert updated.changes["status"] == {"old": "in_use", "new": "maintenance"}

    with inventory(catalog) as assets:
        assets.update(catalog.admin(), created.id, {"name": "Guardado renombrado"})
    assert history(catalog, created.id)[1] == updated
    assert [entry.action for entry in history(catalog, created.id)] == [
        "created",
        "updated",
        "archived",
        "updated",
    ]


def test_history_is_bounded_and_requires_read_permission(catalog: Catalog) -> None:
    created = create(catalog, quick_code="HIS-3")
    with inventory(catalog) as assets:
        for index in range(3):
            assets.update(catalog.admin(), created.id, {"location": f"Rack {index}"})

    with inventory(catalog) as assets:
        page = assets.history(catalog.admin(), created.id, limit=2, offset=1)
    assert page.total == 4
    assert len(page.items) == 2
    assert page.limit == 2 and page.offset == 1

    class Anonymous:
        actor_id = "00000000-0000-0000-0000-000000000000"
        kind = "human"
        username = "ghost"
        display_name = "Ghost"
        role_id = None
        delegated_by = None
        scopes = frozenset()
        execution_id = None
        authorization_ref = None
        session_id = None

    with pytest.raises(PermissionDenied), inventory(catalog) as assets:
        assets.history(Anonymous(), created.id)

    with pytest.raises(NotFound), inventory(catalog) as assets:
        assets.history(catalog.admin(), "not-an-id")


# ------------------------------------------------------------ eliminación final
def test_purge_in_development_or_test_needs_an_explicit_confirmation(catalog: Catalog) -> None:
    created = create(catalog, quick_code="PURGE-1")

    with pytest.raises(ValidationFailed), inventory(catalog) as assets:
        assets.purge(catalog.admin(), created.id)
    assert catalog.asset_count() == 1

    with inventory(catalog) as assets:
        purged = assets.purge(catalog.admin(), created.id, confirm=True)

    assert purged.asset_id == created.id
    assert purged.quick_code == "PURGE-1"
    assert catalog.asset_count() == 0
    with inventory(catalog) as assets, pytest.raises(NotFound):
        assets.get(catalog.admin(), created.id)


def test_purge_keeps_history_and_a_tombstone_so_the_id_is_never_reused(
    catalog: Catalog,
) -> None:
    created = create(catalog, quick_code="PURGE-2")
    with inventory(catalog) as assets:
        assets.update(catalog.admin(), created.id, {"status": "retired"})
        assets.purge(catalog.admin(), created.id, confirm=True, reason="baja definitiva")

    tombstones = rows(
        catalog,
        "SELECT id, quick_code, reason FROM asset_tombstones WHERE id = :id",
        id=created.id,
    )
    assert tombstones == [(created.id, "PURGE-2", "baja definitiva")]

    entries = history(catalog, created.id)
    assert [entry.action for entry in entries] == ["created", "updated", "purged"]
    assert entries[-1].quick_code_old == "PURGE-2"
    assert entries[-1].quick_code_new is None

    with inventory(catalog) as assets:
        page = assets.history(catalog.admin(), created.id)
    assert page.total == 3


def test_production_purge_requires_archive_typed_id_reason_and_permission(
    settings_factory: SettingsFactory,
) -> None:
    catalog = prepare(settings_factory, environment="production")
    with inventory(catalog) as assets:
        created = assets.create(catalog.admin(), asset_values(quick_code="PROD-1"))

    with pytest.raises(Conflict), inventory(catalog) as assets:
        assets.purge(
            catalog.admin(),
            created.id,
            confirm=True,
            typed_id=created.id,
            reason="baja definitiva",
        )

    with inventory(catalog) as assets:
        assets.archive(catalog.admin(), created.id, reason="fin de vida")

    with pytest.raises(ValidationFailed), inventory(catalog) as assets:
        assets.purge(catalog.admin(), created.id, confirm=True, reason="baja definitiva")
    with pytest.raises(ValidationFailed), inventory(catalog) as assets:
        assets.purge(
            catalog.admin(),
            created.id,
            confirm=False,
            typed_id=created.id,
            reason="baja definitiva",
        )
    with pytest.raises(ValidationFailed), inventory(catalog) as assets:
        assets.purge(
            catalog.admin(),
            created.id,
            confirm=True,
            typed_id="00000000-0000-0000-0000-000000000000",
            reason="baja definitiva",
        )
    with pytest.raises(ValidationFailed), inventory(catalog) as assets:
        assets.purge(catalog.admin(), created.id, confirm=True, typed_id=created.id, reason="abc")

    with (
        edit_only_principal(catalog) as operator,
        inventory(catalog) as assets,
        pytest.raises(PermissionDenied),
    ):
        assets.purge(
            operator,
            created.id,
            confirm=True,
            typed_id=created.id,
            reason="baja definitiva",
        )
    assert catalog.asset_count() == 1

    with inventory(catalog) as assets:
        purged = assets.purge(
            catalog.admin(),
            created.id,
            confirm=True,
            typed_id=created.id,
            reason="baja definitiva",
        )
    assert purged.asset_id == created.id
    assert catalog.asset_count() == 0


def test_machine_identities_can_never_purge_even_with_an_explicit_privilege(
    catalog: Catalog,
) -> None:
    with catalog.session() as session:
        role = catalog.service(session).create_role(
            catalog.admin(),
            name="inventario-purga-automatica",
            permissions=["assets.view", "assets.edit", "assets.purge"],
        )
    principal, _ = catalog.add_machine("purge-bot", "Purge Bot", role_id=role.id)
    created = create(catalog, quick_code="PURGE-MACHINE")

    with pytest.raises(PermissionDenied), inventory(catalog) as assets:
        assets.purge(principal, created.id, confirm=True, reason="borrado automático")

    assert catalog.asset_count() == 1
    denied = [event for event in catalog.audit("assets.purge") if event["outcome"] == "denied"]
    assert denied and denied[-1]["actor"] == "purge-bot"


def test_batch_denial_leaves_every_asset_and_counter_unchanged(catalog: Catalog) -> None:
    first = create(catalog, quick_code="BATCH-A")
    second = create(catalog, quick_code="BATCH-B")
    with inventory(catalog) as assets:
        assets.update(catalog.admin(), second.id, {"responsible": "Matriz NOC"})

    history_before = rows(catalog, "SELECT COUNT(*) FROM asset_history")[0][0]

    with (
        edit_only_principal(catalog) as editor,
        inventory(catalog) as assets,
        pytest.raises(PermissionDenied),
    ):
        assets.batch(
            editor,
            update=[
                {"id": first.id, "location": "Rack 9"},
                {"id": second.id, "responsible": "Otro responsable"},
            ],
        )

    assert catalog.asset_count() == 2
    assert rows(catalog, "SELECT COUNT(*) FROM asset_history")[0][0] == history_before
    with inventory(catalog) as assets:
        assert assets.get(catalog.admin(), first.id).location == "Rack 2"
        assert assets.get(catalog.admin(), second.id).responsible == "Matriz NOC"


def test_batch_writes_one_history_row_per_created_and_updated_asset(
    catalog: Catalog,
) -> None:
    existing = create(catalog, quick_code="BATCH-H-1")
    history_before = rows(catalog, "SELECT COUNT(*) FROM asset_history")[0][0]

    with inventory(catalog) as assets:
        result = assets.batch(
            catalog.admin(),
            create=[asset_values(quick_code="BATCH-H-2")],
            update=[{"id": existing.id, "status": "maintenance"}],
        )

    assert len(result.created) == 1
    assert len(result.updated) == 1
    assert rows(catalog, "SELECT COUNT(*) FROM asset_history")[0][0] == history_before + 2
    assert [entry.action for entry in history(catalog, existing.id)] == ["created", "updated"]


def test_operator_role_cannot_purge_in_production(
    settings_factory: SettingsFactory,
) -> None:
    catalog = prepare(settings_factory, environment="production")
    catalog.add_user(*OPERATOR)
    operator = catalog.principal(OPERATOR[0])
    with inventory(catalog) as assets:
        created = assets.create(catalog.admin(), asset_values(quick_code="PROD-2"))
        assets.archive(catalog.admin(), created.id)

    with pytest.raises(PermissionDenied), inventory(catalog) as assets:
        assets.purge(
            operator, created.id, confirm=True, typed_id=created.id, reason="baja definitiva"
        )

    assert scalar(catalog, "SELECT COUNT(*) FROM assets") == 1
