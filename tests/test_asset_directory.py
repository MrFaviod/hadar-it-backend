"""Canonical asset organization: directory references, positions, assignments, transfers."""

from __future__ import annotations

from collections.abc import Callable
from datetime import UTC, datetime
from typing import Any

import pytest
from itsm.config import Settings
from itsm.directory.service import DirectoryService
from itsm.identity.service import Conflict, NotFound, PermissionDenied, ValidationFailed
from itsm.inventory.service import InventoryService
from sqlalchemy import text
from tests.inventory_support import OPERATOR, READER, Catalog, asset_values, prepare

SettingsFactory = Callable[..., Settings]

EFFECTIVE = datetime(2026, 6, 1, 9, 0, tzinfo=UTC)


@pytest.fixture
def catalog(settings_factory: SettingsFactory) -> Catalog:
    return prepare(settings_factory)


# ----------------------------------------------------------------- helpers
def write(catalog: Catalog, operation: Callable[[Any], Any]) -> Any:
    session = catalog.factory()()
    try:
        result = operation(session)
        session.commit()
        return result
    finally:
        session.close()


def read(catalog: Catalog, operation: Callable[[Any], Any]) -> Any:
    session = catalog.factory()()
    try:
        return operation(session)
    finally:
        session.close()


def directory(catalog: Catalog, operation: Callable[[DirectoryService], Any]) -> Any:
    def run(session: Any) -> Any:
        service = DirectoryService(session, catalog.settings, identity=catalog.service(session))
        return operation(service)

    return write(catalog, run)


def inventory(
    catalog: Catalog, operation: Callable[[InventoryService], Any], *, source: str = "internal"
) -> Any:
    def run(session: Any) -> Any:
        service = InventoryService(
            session,
            catalog.settings,
            identity=catalog.service(session),
            source=source,
        )
        return operation(service)

    return write(catalog, run)


def inventory_read(catalog: Catalog, operation: Callable[[InventoryService], Any]) -> Any:
    def run(session: Any) -> Any:
        return operation(
            InventoryService(session, catalog.settings, identity=catalog.service(session))
        )

    return read(catalog, run)


def make_site(catalog: Catalog, name: str = "Sede Central", **overrides: Any) -> str:
    values = {"level": "site", "name": name, **overrides}
    return directory(catalog, lambda service: service.create_location(catalog.admin(), values)).id


def make_child(catalog: Catalog, parent_id: str, level: str, name: str) -> str:
    values = {"level": level, "name": name, "parent_id": parent_id}
    return directory(catalog, lambda service: service.create_location(catalog.admin(), values)).id


def make_person(catalog: Catalog, name: str = "Ana Pérez", **overrides: Any) -> str:
    values = {"name": name, **overrides}
    return directory(catalog, lambda service: service.create_person(catalog.admin(), values)).id


def create_asset(catalog: Catalog, **overrides: Any) -> Any:
    return inventory(
        catalog, lambda service: service.create(catalog.admin(), asset_values(**overrides))
    )


def history(catalog: Catalog, asset_id: str) -> list[Any]:
    return list(
        inventory_read(catalog, lambda service: service.history(catalog.admin(), asset_id)).items
    )


def scalar(catalog: Catalog, statement: str, **parameters: Any) -> Any:
    with catalog.engine.connect() as connection:
        return connection.execute(text(statement), parameters).scalar_one()


def audit_count(catalog: Catalog, action: str) -> int:
    return int(
        scalar(
            catalog,
            "SELECT COUNT(*) FROM identity_audit_events WHERE action = :action",
            action=action,
        )
    )


def history_count(catalog: Catalog) -> int:
    return int(scalar(catalog, "SELECT COUNT(*) FROM asset_history"))


def stored(catalog: Catalog, asset_id: str) -> Any:
    return scalar(
        catalog,
        "SELECT COALESCE(site_id, '-') || '|' || COALESCE(location_id, '-') || '|' || "
        "COALESCE(responsible_person_id, '-') || '|' || COALESCE(position_x, '-') "
        "FROM assets WHERE id = :id",
        id=asset_id,
    )


def hierarchy(catalog: Catalog) -> tuple[str, str, str, str]:
    """One site, one building, one room inside that building and a second site."""
    site = make_site(catalog, "Sede Central", latitude=-25.286, longitude=-57.647)
    building = make_child(catalog, site, "building", "Edificio A")
    floor = make_child(catalog, building, "floor", "Piso 1")
    room = make_child(catalog, floor, "room_zone", "Sala de servidores")
    other_site = make_site(catalog, "Sede Este")
    return site, building, room, other_site


# ------------------------------------------------------------ references
def test_create_binds_canonical_references_and_derives_labels(catalog: Catalog) -> None:
    site, _, room, _ = hierarchy(catalog)
    person = make_person(catalog, "Ana Pérez", job_title="Jefa de infraestructura")

    created = create_asset(
        catalog,
        site=None,
        location=None,
        responsible=None,
        site_id=site,
        location_id=room,
        responsible_person_id=person,
        position_x="0.25",
        position_y="0.5",
    )

    payload = created.as_payload()
    assert payload["siteId"] == site
    assert payload["locationId"] == room
    assert payload["responsiblePersonId"] == person
    assert payload["site"] == "Sede Central"
    assert payload["location"] == "Sala de servidores"
    assert payload["responsible"] == "Ana Pérez (Jefa de infraestructura)"
    assert payload["responsibleLabel"] == "Ana Pérez (Jefa de infraestructura)"
    assert payload["positionX"] == "0.25"
    assert payload["positionY"] == "0.5"

    stored_payload = inventory_read(
        catalog, lambda service: service.get(catalog.admin(), created.id)
    ).as_payload()
    assert stored_payload["siteId"] == site
    assert stored_payload["locationId"] == room


def test_location_only_binding_derives_its_site(catalog: Catalog) -> None:
    site, _, room, _ = hierarchy(catalog)

    created = create_asset(catalog, site=None, location=None, location_id=room)

    assert created.as_payload()["siteId"] == site
    assert created.as_payload()["locationId"] == room
    assert created.as_payload()["site"] == "Sede Central"
    assert created.as_payload()["location"] == "Sala de servidores"


def test_unknown_inactive_or_wrong_level_references_are_rejected(catalog: Catalog) -> None:
    site, building, room, other_site = hierarchy(catalog)
    person = make_person(catalog, "Ana Pérez")
    directory(
        catalog,
        lambda service: service.update_person(
            catalog.admin(), person, {"status": "inactive"}, source="internal"
        ),
    )
    directory(
        catalog,
        lambda service: service.update_location(
            catalog.admin(), other_site, {"active": False}, source="internal"
        ),
    )

    for overrides in (
        {"responsible_person_id": person},
        {"site_id": other_site},
        {"site_id": building},
        {"location_id": site},
    ):
        with pytest.raises(ValidationFailed):
            create_asset(catalog, site=None, location=None, responsible=None, **overrides)

    # An id that does not exist at all is not found, like any other unknown id.
    for overrides in (
        {"responsible_person_id": "00000000-0000-4000-8000-000000000000"},
        {"site_id": "00000000-0000-4000-8000-000000000000"},
    ):
        with pytest.raises(NotFound):
            create_asset(catalog, site=None, location=None, responsible=None, **overrides)

    assert catalog.asset_count() == 0
    assert history_count(catalog) == 0

    # A site-level building cannot be a site reference and a room cannot be one
    # either; both stay bound to a valid active site.
    assert room and building


def test_location_must_descend_from_the_selected_site(catalog: Catalog) -> None:
    _, _, room, other_site = hierarchy(catalog)

    with pytest.raises(ValidationFailed):
        create_asset(catalog, site=None, location=None, site_id=other_site, location_id=room)

    assert catalog.asset_count() == 0


def test_contradictory_id_and_legacy_text_is_rejected(catalog: Catalog) -> None:
    site, _, room, _ = hierarchy(catalog)
    person = make_person(catalog, "Ana Pérez")

    with pytest.raises(ValidationFailed):
        create_asset(catalog, site="Otra sede", site_id=site)
    with pytest.raises(ValidationFailed):
        create_asset(catalog, location="Otro rack", location_id=room)
    with pytest.raises(ValidationFailed):
        create_asset(catalog, responsible="Matriz NOC", responsible_person_id=person)

    assert catalog.asset_count() == 0


def test_legacy_text_switch_clears_the_stale_reference(catalog: Catalog) -> None:
    site, _, room, _ = hierarchy(catalog)
    person = make_person(catalog, "Ana Pérez")
    created = create_asset(
        catalog,
        site=None,
        location=None,
        responsible=None,
        site_id=site,
        location_id=room,
        responsible_person_id=person,
    )

    updated = inventory(
        catalog,
        lambda service: service.update(catalog.admin(), created.id, {"responsible": "Matriz NOC"}),
    )

    payload = updated.as_payload()
    assert payload["responsible"] == "Matriz NOC"
    assert payload["responsiblePersonId"] is None
    assert payload["responsibleLabel"] is None
    assert payload["siteId"] == site
    assert payload["locationId"] == room

    # A text-only site switch drops the canonical site and the room that belonged
    # to it; the legacy text of both dimensions survives on its own.
    moved = inventory(
        catalog,
        lambda service: service.update(catalog.admin(), created.id, {"site": "Sede Norte"}),
    )
    payload = moved.as_payload()
    assert payload["siteId"] is None
    assert payload["site"] == "Sede Norte"
    assert payload["locationId"] is None
    assert payload["location"] is None


def test_position_needs_a_consistent_pair_inside_the_relative_band(catalog: Catalog) -> None:
    _, _, room, _ = hierarchy(catalog)

    for overrides in (
        {"position_x": "0.5"},
        {"position_y": "0.5"},
        {"position_x": "0.5", "position_y": "1.5"},
        {"position_x": "-0.1", "position_y": "0.5"},
        {"position_x": "0.1234567", "position_y": "0.5"},
        {"position_x": "0.5", "position_y": "0.5"},
    ):
        with pytest.raises(ValidationFailed):
            create_asset(catalog, site=None, location=None, **overrides)

    created = create_asset(
        catalog, site=None, location=None, location_id=room, position_x="0.50", position_y="1"
    )
    assert created.as_payload()["positionX"] == "0.5"
    assert created.as_payload()["positionY"] == "1"


# ------------------------------------------------------------ assignment
def test_assign_and_return_are_atomic_with_history_and_audit(catalog: Catalog) -> None:
    site, _, room, _ = hierarchy(catalog)
    person = make_person(catalog, "Ana Pérez")
    created = create_asset(catalog, site=None, location=None, location_id=room, site_id=site)
    before_history = history_count(catalog)

    assigned = inventory(
        catalog,
        lambda service: service.assign_responsible(
            catalog.admin(),
            created.id,
            person,
            reason="entrega de equipamiento",
            notes="firmado en recepción",
            effective_at=EFFECTIVE,
        ),
    )

    payload = assigned.as_payload()
    assert payload["responsiblePersonId"] == person
    assert payload["responsibleLabel"] == "Ana Pérez"
    assert payload["responsible"] == "Ana Pérez"
    assert history_count(catalog) == before_history + 1
    entry = history(catalog, created.id)[-1]
    assert entry.action == "assigned"
    assert entry.changes["responsible_person_id"] == {"old": None, "new": person}
    assert entry.reason == "entrega de equipamiento"
    assert entry.notes == "firmado en recepción"
    assert entry.effective_at == EFFECTIVE
    assert entry.source == "internal"
    assert audit_count(catalog, "inventory.responsible_assigned") == 1

    returned = inventory(
        catalog,
        lambda service: service.return_responsible(
            catalog.admin(), created.id, reason="fin de comodato", effective_at=EFFECTIVE
        ),
    )
    payload = returned.as_payload()
    assert payload["responsiblePersonId"] is None
    assert payload["responsibleLabel"] is None
    assert payload["responsible"] is None
    entry = history(catalog, created.id)[-1]
    assert entry.action == "returned"
    assert entry.changes["responsible_person_id"] == {"old": person, "new": None}
    assert audit_count(catalog, "inventory.responsible_returned") == 1

    with pytest.raises(Conflict):
        inventory(
            catalog,
            lambda service: service.return_responsible(catalog.admin(), created.id),
        )


def test_assign_denied_leaves_asset_history_and_counters_untouched(catalog: Catalog) -> None:
    person = make_person(catalog, "Ana Pérez")
    created = create_asset(catalog)
    catalog.add_user(*OPERATOR)
    operator = catalog.principal(OPERATOR[0])
    catalog.add_user(*READER)
    reader = catalog.principal(READER[0])
    before = (stored(catalog, created.id), history_count(catalog))

    with pytest.raises(PermissionDenied):
        inventory(
            catalog,
            lambda service: service.assign_responsible(reader, created.id, person),
        )

    assert (stored(catalog, created.id), history_count(catalog)) == before
    assert audit_count(catalog, "inventory.responsible_assigned") == 0

    allowed = inventory(
        catalog, lambda service: service.assign_responsible(operator, created.id, person)
    )
    assert allowed.as_payload()["responsiblePersonId"] == person


def test_retire_clears_the_canonical_person_reference(catalog: Catalog) -> None:
    person = make_person(catalog, "Ana Pérez")
    created = create_asset(
        catalog, responsible_person_id=person, responsible=None, site=None, location=None
    )

    retired = inventory(
        catalog,
        lambda service: service.retire(catalog.admin(), created.id, reason="equipo obsoleto"),
    )

    assert retired.as_payload()["responsiblePersonId"] is None
    assert retired.as_payload()["responsible"] is None
    entry = history(catalog, created.id)[-1]
    assert entry.action == "retired"
    assert entry.changes["responsible_person_id"] == {"old": person, "new": None}


# -------------------------------------------------------------- transfer
def test_transfer_keeps_uuid_and_records_one_structured_event(catalog: Catalog) -> None:
    site, _, room, other_site = hierarchy(catalog)
    new_building = make_child(catalog, other_site, "building", "Edificio Este")
    new_room = make_child(catalog, new_building, "floor", "Piso 3")
    created = create_asset(catalog, site=None, location=None, site_id=site, location_id=room)
    before_history = history_count(catalog)

    transferred = inventory(
        catalog,
        lambda service: service.transfer(
            catalog.admin(),
            created.id,
            site_id=other_site,
            location_id=new_room,
            reason="mudanza de sala",
            notes="camión propio",
            effective_at=EFFECTIVE,
        ),
    )

    payload = transferred.as_payload()
    assert payload["id"] == created.id
    assert payload["quickCode"] == created.quick_code
    assert payload["siteId"] == other_site
    assert payload["locationId"] == new_room
    assert payload["site"] == "Sede Este"
    assert payload["location"] == "Piso 3"
    assert history_count(catalog) == before_history + 1
    entry = history(catalog, created.id)[-1]
    assert entry.action == "transferred"
    assert entry.changes["site_id"] == {"old": site, "new": other_site}
    assert entry.changes["location_id"] == {"old": room, "new": new_room}
    assert entry.reason == "mudanza de sala"
    assert entry.notes == "camión propio"
    assert entry.effective_at == EFFECTIVE
    assert audit_count(catalog, "inventory.asset_transferred") == 1


def test_transfer_to_site_clears_a_location_of_the_previous_site(catalog: Catalog) -> None:
    site, _, room, other_site = hierarchy(catalog)
    created = create_asset(catalog, site=None, location=None, site_id=site, location_id=room)

    transferred = inventory(
        catalog,
        lambda service: service.transfer(
            catalog.admin(), created.id, site_id=other_site, reason="traslado de sede"
        ),
    )

    payload = transferred.as_payload()
    assert payload["siteId"] == other_site
    assert payload["locationId"] is None
    assert payload["location"] is None
    entry = history(catalog, created.id)[-1]
    assert entry.changes["location_id"] == {"old": room, "new": None}


def test_transfer_validates_the_location_inside_the_effective_site(catalog: Catalog) -> None:
    _, _, room, other_site = hierarchy(catalog)

    with pytest.raises(ValidationFailed):
        create_asset(catalog, site=None, location=None, site_id=other_site, location_id=room)

    created = create_asset(catalog)
    with pytest.raises(NotFound):
        inventory(
            catalog,
            lambda service: service.transfer(
                catalog.admin(),
                created.id,
                location_id="00000000-0000-4000-8000-000000000000",
                reason="destino inexistente",
            ),
        )
    assert stored(catalog, created.id).endswith("|-")


# ---------------------------------------------------------- bounded reads
def test_assets_by_person_and_hierarchy_are_filtered_and_bounded(catalog: Catalog) -> None:
    site, building, _, other_site = hierarchy(catalog)
    floor = make_child(catalog, building, "floor", "Piso 7")
    room = make_child(catalog, floor, "room_zone", "Sala dos")
    person = make_person(catalog, "Ana Pérez")
    first = create_asset(
        catalog, quick_code="ORG-1", site=None, location=None, site_id=site, location_id=room
    )
    second = create_asset(catalog, quick_code="ORG-2", site=None, location=None, site_id=other_site)
    third = create_asset(
        catalog,
        quick_code="ORG-3",
        responsible_person_id=person,
        responsible=None,
        site=None,
        location=None,
    )

    by_site = inventory_read(
        catalog,
        lambda service: service.search(catalog.admin(), site_id=site),
    )
    assert [item.id for item in by_site.items] == [first.id]
    assert by_site.total == 1

    by_location = inventory_read(
        catalog,
        lambda service: service.search(catalog.admin(), location_id=building),
    )
    assert {item.id for item in by_location.items} == {first.id}

    by_person = inventory_read(
        catalog,
        lambda service: service.search(catalog.admin(), responsible_person_id=person),
    )
    assert [item.id for item in by_person.items] == [third.id]

    assert second.as_payload()["siteId"] == other_site
    with pytest.raises(ValidationFailed):
        inventory_read(
            catalog,
            lambda service: service.search(catalog.admin(), location_id=site, limit=0),
        )


def test_map_returns_sites_and_bounded_positions(catalog: Catalog) -> None:
    site, _, room, other_site = hierarchy(catalog)
    create_asset(
        catalog,
        quick_code="MAP-1",
        site=None,
        location=None,
        site_id=site,
        location_id=room,
        position_x="0.1",
        position_y="0.2",
    )
    create_asset(catalog, quick_code="MAP-2", site=None, location=None, site_id=other_site)

    payload = inventory_read(catalog, lambda service: service.map(catalog.admin())).as_payload()

    assert [entry["id"] for entry in payload["sites"]] == [site, other_site]
    assert payload["sites"][0]["latitude"] == -25.286
    assert payload["sites"][0]["longitude"] == -57.647
    assert len(payload["positions"]) == 1
    position = payload["positions"][0]
    assert position["assetId"]
    assert position["siteId"] == site
    assert position["locationId"] == room
    assert position["x"] == 0.1
    assert position["y"] == 0.2
    assert payload["truncated"] is False

    scoped = inventory_read(
        catalog, lambda service: service.map(catalog.admin(), site_id=other_site)
    ).as_payload()
    assert [entry["id"] for entry in scoped["sites"]] == [other_site]
    assert scoped["positions"] == []


# --------------------------------------------------- directory invariants
def test_directory_deactivation_guard_counts_active_asset_references(catalog: Catalog) -> None:
    site, _, room, _ = hierarchy(catalog)
    person = make_person(catalog, "Ana Pérez")
    created = create_asset(
        catalog,
        site=None,
        location=None,
        responsible=None,
        site_id=site,
        location_id=room,
        responsible_person_id=person,
    )

    with pytest.raises(Conflict):
        directory(
            catalog,
            lambda service: service.update_location(
                catalog.admin(), room, {"active": False}, source="internal"
            ),
        )
    with pytest.raises(Conflict):
        directory(
            catalog,
            lambda service: service.update_person(
                catalog.admin(), person, {"status": "inactive"}, source="internal"
            ),
        )

    inventory(
        catalog,
        lambda service: service.archive(catalog.admin(), created.id, reason="fuera de servicio"),
    )

    archived_room = directory(
        catalog,
        lambda service: service.update_location(
            catalog.admin(), room, {"active": False}, source="internal"
        ),
    )
    assert archived_room.as_payload()["active"] is False
    inactive = directory(
        catalog,
        lambda service: service.update_person(
            catalog.admin(), person, {"status": "inactive"}, source="internal"
        ),
    )
    assert inactive.as_payload()["status"] == "inactive"


def test_sparse_and_legacy_assets_keep_working(catalog: Catalog) -> None:
    created = create_asset(catalog)
    payload = created.as_payload()
    assert payload["siteId"] is None
    assert payload["locationId"] is None
    assert payload["responsiblePersonId"] is None
    assert payload["responsibleLabel"] is None
    assert payload["positionX"] is None
    assert payload["positionY"] is None
    assert payload["site"] == "Sede Norte"
    assert payload["responsible"] == "Matriz NOC"
    assert payload["cost"] is None
    assert payload["technical"] is None

    updated = inventory(
        catalog,
        lambda service: service.update(
            catalog.admin(),
            created.id,
            {"category": "servidores", "cost": "120.50", "technical": {"ram": 16}},
        ),
    )
    assert updated.as_payload()["category"] == "servidores"
    assert updated.as_payload()["cost"] == "120.50"
    assert updated.as_payload()["technical"] == {"ram": 16}


# ------------------------------------------------------- archived lifecycle
def test_archived_asset_refuses_new_bindings_but_still_accepts_a_return(
    catalog: Catalog,
) -> None:
    _, _, room, other_site = hierarchy(catalog)
    person = make_person(catalog)
    created = create_asset(
        catalog,
        site=None,
        location=None,
        responsible=None,
        location_id=room,
        responsible_person_id=person,
    )
    asset_id = created.id
    inventory(
        catalog,
        lambda service: service.archive(catalog.admin(), asset_id, reason="guardado"),
    )

    before = stored(catalog, asset_id)
    before_history = history_count(catalog)
    other_person = make_person(catalog, "Beto Ruiz")

    with pytest.raises(Conflict):
        inventory(
            catalog,
            lambda service: service.assign_responsible(catalog.admin(), asset_id, other_person),
        )
    with pytest.raises(Conflict):
        inventory(
            catalog,
            lambda service: service.transfer(catalog.admin(), asset_id, site_id=other_site),
        )

    assert stored(catalog, asset_id) == before
    assert history_count(catalog) == before_history

    returned = inventory(
        catalog, lambda service: service.return_responsible(catalog.admin(), asset_id)
    )
    assert returned.as_payload()["responsiblePersonId"] is None
    assert returned.as_payload()["locationId"] == room

    inventory(catalog, lambda service: service.restore(catalog.admin(), asset_id))
    reassigned = inventory(
        catalog,
        lambda service: service.assign_responsible(catalog.admin(), asset_id, other_person),
    )
    assert reassigned.as_payload()["responsiblePersonId"] == other_person


# ------------------------------------------------- clearing and legacy switches
def test_explicit_person_clear_clears_the_reference_and_its_mirrored_text(
    catalog: Catalog,
) -> None:
    person = make_person(catalog, "Ana Pérez")
    cleared_by_id = create_asset(
        catalog, site=None, location=None, responsible_person_id=person, responsible=None
    )
    cleared_by_text = create_asset(
        catalog,
        quick_code="SW-SN-002",
        site=None,
        location=None,
        responsible_person_id=person,
        responsible=None,
    )

    for asset_id, changes in (
        (cleared_by_id.id, {"responsible_person_id": None}),
        (cleared_by_text.id, {"responsible": None}),
    ):
        updated = inventory(
            catalog,
            lambda service, asset_id=asset_id, changes=changes: service.update(
                catalog.admin(), asset_id, changes
            ),
        )
        payload = updated.as_payload()
        assert payload["responsiblePersonId"] is None
        assert payload["responsible"] is None
        assert payload["responsibleLabel"] is None
        entry = history(catalog, asset_id)[-1]
        assert entry.action == "updated"
        assert entry.changes["responsible_person_id"] == {"old": person, "new": None}
        assert entry.changes["responsible"] == {"old": "Ana Pérez", "new": None}

    assert audit_count(catalog, "inventory.asset_updated") == 2
    assert catalog.asset_count() == 2


def test_clearing_or_switching_the_site_drops_its_location_and_position(
    catalog: Catalog,
) -> None:
    site, _, room, _ = hierarchy(catalog)
    cleared = create_asset(
        catalog,
        site=None,
        location=None,
        site_id=site,
        location_id=room,
        position_x="0.2",
        position_y="0.3",
    )
    switched = create_asset(
        catalog,
        quick_code="SW-SN-002",
        site=None,
        location=None,
        site_id=site,
        location_id=room,
        position_x="0.4",
        position_y="0.5",
    )

    cleared_payload = inventory(
        catalog,
        lambda service: service.update(catalog.admin(), cleared.id, {"site_id": None}),
    ).as_payload()
    assert cleared_payload["siteId"] is None
    assert cleared_payload["site"] is None
    assert cleared_payload["locationId"] is None
    assert cleared_payload["location"] is None
    assert cleared_payload["positionX"] is None
    assert cleared_payload["positionY"] is None
    entry = history(catalog, cleared.id)[-1]
    assert entry.changes["site_id"] == {"old": site, "new": None}
    assert entry.changes["location_id"] == {"old": room, "new": None}
    assert entry.changes["position_x"] == {"old": "0.2", "new": None}

    switched_payload = inventory(
        catalog,
        lambda service: service.update(catalog.admin(), switched.id, {"site": "Sede Norte"}),
    ).as_payload()
    assert switched_payload["siteId"] is None
    assert switched_payload["site"] == "Sede Norte"
    assert switched_payload["locationId"] is None
    assert switched_payload["location"] is None
    assert switched_payload["positionX"] is None


def test_clearing_the_location_keeps_the_site_of_the_asset(catalog: Catalog) -> None:
    site, _, room, _ = hierarchy(catalog)
    created = create_asset(
        catalog,
        site=None,
        location=None,
        site_id=site,
        location_id=room,
        position_x="0.5",
        position_y="0.5",
    )

    payload = inventory(
        catalog,
        lambda service: service.update(catalog.admin(), created.id, {"location_id": None}),
    ).as_payload()

    assert payload["siteId"] == site
    assert payload["site"] == "Sede Central"
    assert payload["locationId"] is None
    assert payload["location"] is None
    assert payload["positionX"] is None
    assert payload["positionY"] is None


def test_explicit_null_reference_with_legacy_text_switches_to_text_only(
    catalog: Catalog,
) -> None:
    site, _, room, _ = hierarchy(catalog)
    person = make_person(catalog, "Ana Pérez")
    created = create_asset(
        catalog,
        site=None,
        location=None,
        site_id=site,
        location_id=room,
        responsible_person_id=person,
        responsible=None,
        position_x="0.1",
        position_y="0.2",
    )

    payload = inventory(
        catalog,
        lambda service: service.update(
            catalog.admin(),
            created.id,
            {
                "site_id": None,
                "site": "Sede Norte",
                "location_id": None,
                "location": "Depósito",
                "responsible_person_id": None,
                "responsible": "Matriz NOC",
            },
        ),
    ).as_payload()

    assert payload["siteId"] is None
    assert payload["site"] == "Sede Norte"
    assert payload["locationId"] is None
    assert payload["location"] == "Depósito"
    assert payload["responsiblePersonId"] is None
    assert payload["responsible"] == "Matriz NOC"
    assert payload["responsibleLabel"] is None
    assert payload["positionX"] is None
    assert payload["positionY"] is None


def test_legacy_site_text_must_agree_with_an_explicit_location(catalog: Catalog) -> None:
    site, _, room, _ = hierarchy(catalog)
    created = create_asset(catalog, site=None, location=None, site_id=site, location_id=room)
    before = (stored(catalog, created.id), history_count(catalog))

    with pytest.raises(ValidationFailed):
        inventory(
            catalog,
            lambda service: service.update(
                catalog.admin(), created.id, {"site": "Sede Norte", "location_id": room}
            ),
        )

    assert (stored(catalog, created.id), history_count(catalog)) == before
    assert audit_count(catalog, "inventory.asset_updated") == 0


# ------------------------------------------------------------- restore guards
def test_restore_revalidates_the_stored_directory_references(catalog: Catalog) -> None:
    site = make_site(catalog, "Sede Central")
    building = make_child(catalog, site, "building", "Edificio A")
    floor = make_child(catalog, building, "floor", "Piso 1")
    room = make_child(catalog, floor, "room_zone", "Sala de servidores")
    person = make_person(catalog, "Ana Pérez")
    created = create_asset(
        catalog,
        site=None,
        location=None,
        site_id=site,
        location_id=room,
        responsible_person_id=person,
        responsible=None,
    )
    asset_id = created.id
    inventory(
        catalog, lambda service: service.archive(catalog.admin(), asset_id, reason="guardado")
    )
    directory(
        catalog,
        lambda service: service.update_person(
            catalog.admin(), person, {"status": "inactive"}, source="internal"
        ),
    )
    before = (stored(catalog, asset_id), history_count(catalog))

    with pytest.raises(ValidationFailed):
        inventory(catalog, lambda service: service.restore(catalog.admin(), asset_id))

    assert (stored(catalog, asset_id), history_count(catalog)) == before
    assert audit_count(catalog, "inventory.asset_restored") == 0
    assert (
        inventory_read(
            catalog, lambda service: service.get(catalog.admin(), asset_id)
        ).as_payload()["archived"]
        is True
    )

    directory(
        catalog,
        lambda service: service.update_person(
            catalog.admin(), person, {"status": "active"}, source="internal"
        ),
    )
    directory(
        catalog,
        lambda service: service.update_location(
            catalog.admin(), room, {"active": False}, source="internal"
        ),
    )
    with pytest.raises(ValidationFailed):
        inventory(catalog, lambda service: service.restore(catalog.admin(), asset_id))
    assert stored(catalog, asset_id) == before[0]

    # A location that the directory later moved under another site is not a
    # usable restoration target either (the same active validators apply).
    directory(
        catalog,
        lambda service: service.update_location(
            catalog.admin(), room, {"active": True}, source="internal"
        ),
    )
    other_site = make_site(catalog, "Sede Este")
    other_building = make_child(catalog, other_site, "building", "Edificio Este")
    other_floor = make_child(catalog, other_building, "floor", "Piso 3")
    directory(
        catalog,
        lambda service: service.update_location(
            catalog.admin(), room, {"parent_id": other_floor}, source="internal"
        ),
    )
    with pytest.raises(ValidationFailed):
        inventory(catalog, lambda service: service.restore(catalog.admin(), asset_id))
    assert stored(catalog, asset_id) == before[0]
    assert audit_count(catalog, "inventory.asset_restored") == 0

    directory(
        catalog,
        lambda service: service.update_location(
            catalog.admin(), room, {"parent_id": floor}, source="internal"
        ),
    )
    restored = inventory(catalog, lambda service: service.restore(catalog.admin(), asset_id))
    assert restored.as_payload()["archived"] is False
    assert audit_count(catalog, "inventory.asset_restored") == 1


def test_restore_accepts_reactivated_references_and_sparse_assets(catalog: Catalog) -> None:
    _, _, room, _ = hierarchy(catalog)
    person = make_person(catalog, "Ana Pérez")
    bound = create_asset(
        catalog,
        site=None,
        location=None,
        location_id=room,
        responsible_person_id=person,
        responsible=None,
    )
    sparse = create_asset(catalog, quick_code="SW-SN-002")
    for asset_id in (bound.id, sparse.id):
        inventory(
            catalog,
            lambda service, asset_id=asset_id: service.archive(
                catalog.admin(), asset_id, reason="guardado"
            ),
        )

    directory(
        catalog,
        lambda service: service.update_person(
            catalog.admin(), person, {"status": "inactive"}, source="internal"
        ),
    )
    with pytest.raises(ValidationFailed):
        inventory(catalog, lambda service: service.restore(catalog.admin(), bound.id))
    directory(
        catalog,
        lambda service: service.update_person(
            catalog.admin(), person, {"status": "active"}, source="internal"
        ),
    )

    restored = inventory(catalog, lambda service: service.restore(catalog.admin(), bound.id))
    assert restored.as_payload()["archived"] is False
    assert restored.as_payload()["responsiblePersonId"] == person
    assert restored.as_payload()["locationId"] == room

    sparse_restored = inventory(
        catalog, lambda service: service.restore(catalog.admin(), sparse.id)
    )
    assert sparse_restored.as_payload()["archived"] is False
    assert sparse_restored.as_payload()["siteId"] is None
    assert audit_count(catalog, "inventory.asset_restored") == 2


# ------------------------------------------------------------ derived labels
def test_public_reads_derive_current_directory_labels(catalog: Catalog) -> None:
    site, _, room, _ = hierarchy(catalog)
    person = make_person(catalog, "Ana Pérez", job_title="Jefa de infraestructura")
    created = create_asset(
        catalog,
        site=None,
        location=None,
        site_id=site,
        location_id=room,
        responsible_person_id=person,
        responsible=None,
    )
    created_payload = created.as_payload()
    events = history_count(catalog)

    directory(
        catalog,
        lambda service: service.update_location(
            catalog.admin(), room, {"name": "Sala 9"}, source="internal"
        ),
    )
    directory(
        catalog,
        lambda service: service.update_location(
            catalog.admin(), site, {"name": "Sede Sur"}, source="internal"
        ),
    )
    directory(
        catalog,
        lambda service: service.update_person(
            catalog.admin(), person, {"job_title": "Coordinadora"}, source="internal"
        ),
    )

    payload = inventory_read(
        catalog, lambda service: service.get(catalog.admin(), created.id)
    ).as_payload()
    assert payload["site"] == "Sede Sur"
    assert payload["location"] == "Sala 9"
    assert payload["responsible"] == "Ana Pérez (Coordinadora)"
    assert payload["responsibleLabel"] == "Ana Pérez (Coordinadora)"
    assert payload["siteId"] == site
    assert payload["locationId"] == room
    assert payload["responsiblePersonId"] == person
    assert payload["updatedAt"] == created_payload["updatedAt"]
    assert history_count(catalog) == events

    listing = inventory_read(catalog, lambda service: service.search(catalog.admin())).as_payload()
    assert [item["location"] for item in listing["items"]] == ["Sala 9"]
    assert [item["responsible"] for item in listing["items"]] == ["Ana Pérez (Coordinadora)"]

    cloned = inventory(
        catalog, lambda service: service.clone(catalog.admin(), created.id)
    ).as_payload()
    assert cloned["site"] == "Sede Sur"
    assert cloned["location"] == "Sala 9"
    assert cloned["responsible"] == "Ana Pérez (Coordinadora)"
    assert cloned["siteId"] == site


def test_legacy_text_and_archived_references_keep_reading(catalog: Catalog) -> None:
    site, _, room, _ = hierarchy(catalog)
    legacy = create_asset(catalog)
    legacy_payload = legacy.as_payload()
    assert legacy_payload["site"] == "Sede Norte"
    assert legacy_payload["location"] == "Rack 2"

    bound = create_asset(
        catalog, quick_code="SW-SN-002", site=None, location=None, site_id=site, location_id=room
    )
    inventory(
        catalog,
        lambda service: service.archive(catalog.admin(), bound.id, reason="fuera de servicio"),
    )
    directory(
        catalog,
        lambda service: service.update_location(
            catalog.admin(), room, {"active": False}, source="internal"
        ),
    )

    archived_payload = inventory_read(
        catalog, lambda service: service.get(catalog.admin(), bound.id)
    ).as_payload()
    assert archived_payload["archived"] is True
    assert archived_payload["site"] == "Sede Central"
    assert archived_payload["location"] == "Sala de servidores"

    legacy_after = inventory_read(
        catalog, lambda service: service.get(catalog.admin(), legacy.id)
    ).as_payload()
    assert legacy_after["site"] == "Sede Norte"
    assert legacy_after["location"] == "Rack 2"
    assert legacy_after["siteId"] is None


# ---------------------------------------------------- transfer characterization
def test_transfer_may_reallocate_the_formatted_quick_code(catalog: Catalog) -> None:
    site, _, room, other_site = hierarchy(catalog)
    created = create_asset(
        catalog,
        quick_code=None,
        category="switches",
        site=None,
        location=None,
        site_id=site,
        location_id=room,
        technical={"ports": 24},
    )
    payload = created.as_payload()
    assert payload["quickCode"] == "SED-SW-01"
    stored_id = payload["id"]
    technical = payload["technical"]

    transferred = inventory(
        catalog,
        lambda service: service.transfer(catalog.admin(), stored_id, site_id=other_site),
    ).as_payload()

    assert transferred["id"] == stored_id
    assert transferred["technical"] == technical
    assert transferred["quickCode"] == "SED-SW-02"
    entry = history(catalog, stored_id)[-1]
    assert entry.action == "transferred"
    assert entry.quick_code_old == "SED-SW-01"
    assert entry.quick_code_new == "SED-SW-02"
    assert entry.changes["quick_code"] == {"old": "SED-SW-01", "new": "SED-SW-02"}
    assert entry.changes["site_id"] == {"old": site, "new": other_site}
    assert audit_count(catalog, "inventory.asset_transferred") == 1
