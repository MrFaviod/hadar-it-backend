"""Directory service: people are not accounts, hierarchy rules and structured events."""

from __future__ import annotations

import json
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from datetime import UTC, datetime, timedelta
from typing import Any

import pytest
from itsm.config import Settings
from itsm.directory.service import (
    MAX_LIMIT,
    MAX_TREE_DEPTH,
    MAX_TREE_NODES,
    DirectoryService,
    PersonView,
)
from itsm.identity.service import (
    Conflict,
    IdentityService,
    NotFound,
    PermissionDenied,
    ValidationFailed,
)
from sqlalchemy import text
from tests.inventory_support import READER, Catalog, prepare

SettingsFactory = Callable[..., Settings]


@pytest.fixture
def catalog(settings_factory: SettingsFactory) -> Catalog:
    return prepare(settings_factory)


@contextmanager
def directory(catalog: Catalog) -> Iterator[DirectoryService]:
    """One real session and one real identity service per service call."""
    with catalog.session() as session:
        yield DirectoryService(session, catalog.settings, identity=catalog.service(session))


def rows(catalog: Catalog, table: str) -> int:
    with catalog.engine.connect() as connection:
        return int(connection.execute(text(f"SELECT COUNT(*) FROM {table}")).scalar_one())


def names(catalog: Catalog, table: str, column: str) -> list[str]:
    with catalog.engine.connect() as connection:
        result = connection.execute(text(f"SELECT {column} FROM {table} ORDER BY {column}"))
        return [str(row[0]) for row in result.all()]


def events(catalog: Catalog) -> list[dict[str, Any]]:
    with catalog.engine.connect() as connection:
        result = connection.execute(
            text(
                "SELECT entity, entity_id, action, actor_username, source, "
                "before_snapshot, after_snapshot, recorded_at, effective_at "
                "FROM directory_events ORDER BY recorded_at, id"
            )
        )
        return [
            {
                "entity": row.entity,
                "entity_id": row.entity_id,
                "action": row.action,
                "actor": row.actor_username,
                "source": row.source,
                "before": None if row.before_snapshot is None else json.loads(row.before_snapshot),
                "after": None if row.after_snapshot is None else json.loads(row.after_snapshot),
                "recorded_at": row.recorded_at,
                "effective_at": row.effective_at,
            }
            for row in result.all()
        ]


def audit(catalog: Catalog, action: str) -> list[dict[str, Any]]:
    with catalog.engine.connect() as connection:
        result = connection.execute(
            text(
                "SELECT actor_username, action, outcome FROM identity_audit_events "
                "WHERE action = :action ORDER BY id"
            ),
            {"action": action},
        )
        return [
            {"actor": row.actor_username, "action": row.action, "outcome": row.outcome}
            for row in result.all()
        ]


def make_site(service: DirectoryService, catalog: Catalog, name: str = "Sede Norte") -> Any:
    return service.create_location(catalog.admin(), {"level": "site", "name": name}, source="rest")


def make_child(
    service: DirectoryService,
    catalog: Catalog,
    level: str,
    parent_id: str,
    name: str,
) -> Any:
    return service.create_location(
        catalog.admin(),
        {"level": level, "parent_id": parent_id, "name": name},
        source="rest",
    )


# --------------------------------------------------------------------- people
def test_person_is_created_without_an_access_account(catalog: Catalog) -> None:
    accounts = (rows(catalog, "identity_identities"), rows(catalog, "identity_credentials"))
    with directory(catalog) as service:
        person = service.create_person(
            catalog.admin(),
            {"name": "Ana Benítez", "job_title": "Jefa de Redes"},
            source="rest",
        )

    assert isinstance(person, PersonView)
    assert (person.name, person.job_title, person.status) == (
        "Ana Benítez",
        "Jefa de Redes",
        "active",
    )
    assert (person.department_id, person.site_id, person.contact_email) == (None, None, None)
    assert rows(catalog, "directory_people") == 1
    assert (rows(catalog, "identity_identities"), rows(catalog, "identity_credentials")) == accounts
    recorded = events(catalog)
    assert [(event["entity"], event["action"], event["source"]) for event in recorded] == [
        ("person", "created", "rest")
    ]
    assert recorded[0]["after"] == {
        "name": "Ana Benítez",
        "jobTitle": "Jefa de Redes",
        "departmentId": None,
        "siteId": None,
        "contactEmail": None,
        "contactPhone": None,
        "status": "active",
    }
    assert recorded[0]["before"] is None
    assert audit(catalog, "directory.person_created") == [
        {"actor": "ana.admin", "action": "directory.person_created", "outcome": "success"}
    ]


def test_person_reference_and_contact_fields_stay_sparse(catalog: Catalog) -> None:
    with directory(catalog) as service:
        site = make_site(service, catalog)
        department = service.create_department(catalog.admin(), {"name": "Redes"}, source="rest")
        person = service.create_person(
            catalog.admin(),
            {"name": "Bruno Cáceres", "site_id": site.id},
            source="rest",
        )
        updated = service.update_person(
            catalog.admin(),
            person.id,
            {"department_id": department.id, "contact_email": "bruno@example.invalid"},
            source="rest",
        )

    assert (updated.site_id, updated.department_id) == (site.id, department.id)
    assert updated.job_title is None
    assert updated.contact_email == "bruno@example.invalid"
    assert updated.contact_phone is None


def test_inactive_department_and_unknown_site_are_rejected_as_person_references(
    catalog: Catalog,
) -> None:
    with directory(catalog) as service:
        department = service.create_department(catalog.admin(), {"name": "Redes"}, source="rest")
        service.update_department(catalog.admin(), department.id, {"active": False}, source="rest")
        with pytest.raises(ValidationFailed):
            service.create_person(
                catalog.admin(),
                {"name": "Carla Duarte", "department_id": department.id},
                source="rest",
            )
        with pytest.raises(ValidationFailed):
            service.create_person(
                catalog.admin(),
                {"name": "Carla Duarte", "site_id": "0f8c5f1e-0000-4000-8000-000000000000"},
                source="rest",
            )
        with pytest.raises(ValidationFailed):
            service.create_person(
                catalog.admin(),
                {"name": "Carla Duarte", "site_id": "no-es-un-uuid"},
                source="rest",
            )
        site = make_site(service, catalog)
        building = make_child(service, catalog, "building", site.id, "Edificio A")
        with pytest.raises(ValidationFailed):
            service.create_person(catalog.admin(), {"name": "Carla Duarte", "site_id": building.id})

    assert rows(catalog, "directory_people") == 0
    recorded = events(catalog)
    assert [event["action"] for event in recorded if event["entity"] == "person"] == []
    assert [event["action"] for event in recorded if event["entity"] == "department"] == [
        "created",
        "deactivated",
    ]


def test_person_status_updates_are_non_destructive_and_named(catalog: Catalog) -> None:
    with directory(catalog) as service:
        person = service.create_person(catalog.admin(), {"name": "Diego Franco"}, source="rest")
        deactivated = service.update_person(
            catalog.admin(),
            person.id,
            {"status": "inactive"},
            source="rest",
            reason="Baja temporal",
        )
        reactivated = service.update_person(
            catalog.admin(), person.id, {"status": "active"}, source="rest"
        )
        with pytest.raises(ValidationFailed):
            service.update_person(catalog.admin(), person.id, {"status": "retired"}, source="rest")

    assert deactivated.id == person.id
    assert (deactivated.status, reactivated.status) == ("inactive", "active")
    assert deactivated.created_at == person.created_at
    assert rows(catalog, "directory_people") == 1
    recorded = events(catalog)
    assert [(event["action"], (event["before"] or {}).get("status")) for event in recorded] == [
        ("created", None),
        ("deactivated", "active"),
        ("activated", "inactive"),
    ]
    assert recorded[1]["after"]["status"] == "inactive"


@pytest.mark.parametrize(
    ("reference", "message"),
    [
        ("site", "siteId must reference an active site"),
        ("department", "departmentId must reference an active department"),
    ],
)
def test_person_reactivation_requires_an_active_reference(
    catalog: Catalog, reference: str, message: str
) -> None:
    with directory(catalog) as service:
        site = make_site(service, catalog)
        department = service.create_department(catalog.admin(), {"name": "Redes"}, source="rest")
        person = service.create_person(
            catalog.admin(),
            {"name": "Laura Ruiz", "site_id": site.id, "department_id": department.id},
            source="rest",
        )
        service.update_person(catalog.admin(), person.id, {"status": "inactive"}, source="rest")
        if reference == "site":
            service.update_location(catalog.admin(), site.id, {"active": False}, source="rest")
        else:
            service.update_department(
                catalog.admin(), department.id, {"active": False}, source="rest"
            )
        history_before = service.history(
            catalog.admin(), entity="person", entity_id=person.id
        ).total
        with pytest.raises(ValidationFailed) as rejected:
            service.update_person(catalog.admin(), person.id, {"status": "active"}, source="rest")
        stored = service.get_person(catalog.admin(), person.id)
        history_after = service.history(catalog.admin(), entity="person", entity_id=person.id).total
        if reference == "site":
            service.update_location(catalog.admin(), site.id, {"active": True}, source="rest")
        else:
            service.update_department(
                catalog.admin(), department.id, {"active": True}, source="rest"
            )
        reactivated = service.update_person(
            catalog.admin(), person.id, {"status": "active"}, source="rest"
        )

    assert str(rejected.value) == message
    assert (stored.status, stored.site_id, stored.department_id) == (
        "inactive",
        site.id,
        department.id,
    )
    assert history_before == history_after == 2
    assert reactivated.status == "active"


def test_person_reactivation_uses_the_references_from_the_patch(catalog: Catalog) -> None:
    with directory(catalog) as service:
        closed_site = make_site(service, catalog)
        active_site = make_site(service, catalog, "Sede Sur")
        department = service.create_department(catalog.admin(), {"name": "Redes"}, source="rest")
        person = service.create_person(
            catalog.admin(),
            {"name": "Marco Vera", "site_id": closed_site.id, "department_id": department.id},
            source="rest",
        )
        service.update_person(catalog.admin(), person.id, {"status": "inactive"}, source="rest")
        service.update_location(catalog.admin(), closed_site.id, {"active": False}, source="rest")
        service.update_department(catalog.admin(), department.id, {"active": False}, source="rest")
        reactivated = service.update_person(
            catalog.admin(),
            person.id,
            {"status": "active", "site_id": active_site.id, "department_id": None},
            source="rest",
        )

    assert reactivated.status == "active"
    assert (reactivated.site_id, reactivated.department_id) == (active_site.id, None)


def test_sparse_person_reactivation_needs_no_reference(catalog: Catalog) -> None:
    with directory(catalog) as service:
        person = service.create_person(catalog.admin(), {"name": "Nadia Sosa"}, source="rest")
        service.update_person(catalog.admin(), person.id, {"status": "inactive"}, source="rest")
        reactivated = service.update_person(
            catalog.admin(), person.id, {"status": "active"}, source="rest"
        )

    assert reactivated.status == "active"
    assert (reactivated.site_id, reactivated.department_id) == (None, None)
    assert [event["action"] for event in events(catalog)] == [
        "created",
        "deactivated",
        "activated",
    ]


def test_person_patch_rejects_unknown_field_and_records_nothing(catalog: Catalog) -> None:
    with directory(catalog) as service:
        person = service.create_person(catalog.admin(), {"name": "Elena Gómez"}, source="rest")
        with pytest.raises(ValidationFailed):
            service.update_person(catalog.admin(), person.id, {"nickname": "Lena"}, source="rest")
        with pytest.raises(ValidationFailed):
            service.update_person(catalog.admin(), person.id, {}, source="rest")
        with pytest.raises(ValidationFailed):
            service.update_person(
                catalog.admin(), person.id, {"name": "Elena Gómez"}, source="rest"
            )
        with pytest.raises(ValidationFailed):
            service.create_person(
                catalog.admin(), {"name": "Elena Gómez", "contact_email": "sin-arroba"}
            )
        with pytest.raises(NotFound):
            service.update_person(
                catalog.admin(),
                "0f8c5f1e-0000-4000-8000-000000000000",
                {"name": "Nadie"},
                source="rest",
            )

    assert names(catalog, "directory_people", "name") == ["Elena Gómez"]
    assert [event["action"] for event in events(catalog)] == ["created"]


def test_person_listing_is_bounded_filtered_and_ordered(catalog: Catalog) -> None:
    with directory(catalog) as service:
        for index in range(1, 6):
            service.create_person(catalog.admin(), {"name": f"Persona {index}"}, source="rest")
        service.create_person(catalog.admin(), {"name": "100% Fibra"}, source="rest")
        page = service.list_people(catalog.admin(), limit=2, offset=1)
        wildcard = service.list_people(catalog.admin(), query="100%")
        with pytest.raises(ValidationFailed):
            service.list_people(catalog.admin(), limit=MAX_LIMIT + 1)
        with pytest.raises(ValidationFailed):
            service.list_people(catalog.admin(), limit=0)

    assert page.total == 6
    assert [person.name for person in page.items] == ["Persona 1", "Persona 2"]
    assert (page.limit, page.offset) == (2, 1)
    assert [person.name for person in wildcard.items] == ["100% Fibra"]


def test_person_label_is_canonical_and_requires_an_active_person(catalog: Catalog) -> None:
    with directory(catalog) as service:
        plain = service.create_person(catalog.admin(), {"name": "Fabio Ibarra"}, source="rest")
        titled = service.create_person(
            catalog.admin(),
            {"name": "Gloria Jara", "job_title": "Encargada de Sala"},
            source="rest",
        )
        service.update_person(catalog.admin(), plain.id, {"status": "inactive"}, source="rest")
        assert service.person_label(catalog.admin(), titled.id) == (
            "Gloria Jara (Encargada de Sala)"
        )
        assert service.get_person(catalog.admin(), titled.id).label == (
            "Gloria Jara (Encargada de Sala)"
        )
        assert service.person_label(catalog.admin(), plain.id, require_active=False) == (
            "Fabio Ibarra"
        )
        with pytest.raises(Conflict):
            service.person_label(catalog.admin(), plain.id)
        with pytest.raises(NotFound):
            service.person_label(catalog.admin(), "0f8c5f1e-0000-4000-8000-000000000000")


# ---------------------------------------------------------------- departments
def test_department_names_are_case_insensitively_unique(catalog: Catalog) -> None:
    with directory(catalog) as service:
        service.create_department(catalog.admin(), {"name": "Redes"}, source="rest")
        with pytest.raises(Conflict):
            service.create_department(catalog.admin(), {"name": "  redes "}, source="rest")
        service.create_department(catalog.admin(), {"name": "Sistemas"}, source="rest")
        page = service.list_departments(catalog.admin())

    assert [item.name for item in page.items] == ["Redes", "Sistemas"]
    assert page.total == 2


def test_conflicting_department_rename_changes_nothing(catalog: Catalog) -> None:
    with directory(catalog) as service:
        service.create_department(catalog.admin(), {"name": "Redes"}, source="rest")
        systems = service.create_department(catalog.admin(), {"name": "Sistemas"}, source="rest")
        with pytest.raises(Conflict):
            service.update_department(catalog.admin(), systems.id, {"name": "REDES"}, source="rest")

    assert names(catalog, "directory_departments", "name") == ["Redes", "Sistemas"]
    assert [event["action"] for event in events(catalog)] == ["created", "created"]


def test_department_deactivation_requires_no_active_people(catalog: Catalog) -> None:
    with directory(catalog) as service:
        department = service.create_department(catalog.admin(), {"name": "Redes"}, source="rest")
        person = service.create_person(
            catalog.admin(),
            {"name": "Hugo Lezcano", "department_id": department.id},
            source="rest",
        )
        with pytest.raises(Conflict):
            service.update_department(
                catalog.admin(), department.id, {"active": False}, source="rest"
            )
        service.update_person(catalog.admin(), person.id, {"status": "inactive"}, source="rest")
        deactivated = service.update_department(
            catalog.admin(), department.id, {"active": False}, source="rest"
        )

    assert deactivated.active is False
    assert events(catalog)[-1]["action"] == "deactivated"


# ----------------------------------------------------------------- locations
def test_location_levels_require_their_exact_parent(catalog: Catalog) -> None:
    with directory(catalog) as service:
        site = make_site(service, catalog)
        with pytest.raises(ValidationFailed):
            service.create_location(
                catalog.admin(), {"level": "site", "name": "Sede", "parent_id": site.id}
            )
        with pytest.raises(ValidationFailed):
            service.create_location(catalog.admin(), {"level": "building", "name": "Edificio"})
        with pytest.raises(ValidationFailed):
            service.create_location(
                catalog.admin(),
                {"level": "floor", "parent_id": site.id, "name": "Piso 1"},
            )
        with pytest.raises(ValidationFailed):
            service.create_location(catalog.admin(), {"level": "attic", "name": "Techo"})
        building = make_child(service, catalog, "building", site.id, "Edificio A")
        other_site = make_site(service, catalog, "Sede Sur")
        with pytest.raises(Conflict):
            make_child(service, catalog, "building", site.id, " edificio a ")
        make_child(service, catalog, "building", other_site.id, "Edificio A")
        floor = make_child(service, catalog, "floor", building.id, "Piso 1")
        room = make_child(service, catalog, "room_zone", floor.id, "Sala de servidores")

    assert (building.level, building.parent_id) == ("building", site.id)
    assert (floor.level, floor.parent_id) == ("floor", building.id)
    assert (room.level, room.parent_id) == ("room_zone", floor.id)
    assert rows(catalog, "directory_locations") == 6


def test_location_reparent_rejects_cycles_and_level_mismatch(catalog: Catalog) -> None:
    with directory(catalog) as service:
        site = make_site(service, catalog)
        other = make_site(service, catalog, "Sede Sur")
        building = make_child(service, catalog, "building", site.id, "Edificio A")
        floor = make_child(service, catalog, "floor", building.id, "Piso 1")
        with pytest.raises(ValidationFailed):
            service.update_location(
                catalog.admin(), site.id, {"parent_id": floor.id}, source="rest"
            )
        with pytest.raises(ValidationFailed):
            service.update_location(
                catalog.admin(), building.id, {"parent_id": floor.id}, source="rest"
            )
        moved = service.update_location(
            catalog.admin(), building.id, {"parent_id": other.id}, source="rest"
        )
        with pytest.raises(ValidationFailed):
            service.update_location(catalog.admin(), building.id, {"level": "site"}, source="rest")

    assert moved.parent_id == other.id
    assert events(catalog)[-1]["action"] == "updated"

    with catalog.engine.begin() as connection:
        connection.execute(
            text("UPDATE directory_locations SET parent_id = :parent WHERE id = :child"),
            {"parent": building.id, "child": site.id},
        )
    with directory(catalog) as service, pytest.raises(Conflict):
        service.update_location(catalog.admin(), building.id, {"parent_id": site.id}, source="rest")


def test_site_coordinates_require_a_finite_pair_in_bounds(catalog: Catalog) -> None:
    with directory(catalog) as service:
        site = make_site(service, catalog)
        building = make_child(service, catalog, "building", site.id, "Edificio A")
        for invalid in (
            {"latitude": float("nan"), "longitude": 0.0},
            {"latitude": 0.0, "longitude": float("inf")},
            {"latitude": 90.5, "longitude": 0.0},
            {"latitude": 0.0, "longitude": -180.5},
        ):
            with pytest.raises(ValidationFailed):
                service.create_location(
                    catalog.admin(), {"level": "site", "name": "Otra", **invalid}
                )
        with pytest.raises(ValidationFailed):
            service.create_location(
                catalog.admin(), {"level": "site", "name": "Otra", "latitude": 25.28}
            )
        with pytest.raises(ValidationFailed):
            service.update_location(
                catalog.admin(),
                building.id,
                {"latitude": 25.28, "longitude": -57.63},
                source="rest",
            )
        located = service.update_location(
            catalog.admin(),
            site.id,
            {"latitude": 25.2867, "longitude": -57.3333},
            source="rest",
        )
        other = make_site(service, catalog, "Otra Sede")
        with pytest.raises(ValidationFailed):
            service.update_location(catalog.admin(), other.id, {"latitude": 26.0}, source="rest")
        cleared = service.update_location(
            catalog.admin(),
            site.id,
            {"latitude": None, "longitude": None},
            source="rest",
        )

    assert (located.latitude, located.longitude) == (25.2867, -57.3333)
    assert located.as_payload()["latitude"] == 25.2867
    assert (cleared.latitude, cleared.longitude) == (None, None)


def test_plan_reference_rejects_paths_and_urls(catalog: Catalog) -> None:
    with directory(catalog) as service:
        site = make_site(service, catalog)
        for invalid in ("/srv/planos/a.pdf", "../planos/a.pdf", "https://x/a.pdf"):
            with pytest.raises(ValidationFailed):
                service.update_location(
                    catalog.admin(), site.id, {"plan_ref": invalid}, source="rest"
                )
        stored = service.update_location(
            catalog.admin(),
            site.id,
            {"plan_ref": "PLANO-SN-2026", "plan_page": "P3"},
            source="rest",
        )

    assert (stored.plan_ref, stored.plan_page) == ("PLANO-SN-2026", "P3")
    assert events(catalog)[-1]["after"]["planRef"] == "PLANO-SN-2026"


def test_location_deactivation_requires_no_active_children_or_people(catalog: Catalog) -> None:
    with directory(catalog) as service:
        site = make_site(service, catalog)
        building = make_child(service, catalog, "building", site.id, "Edificio A")
        person = service.create_person(
            catalog.admin(), {"name": "Irene Maidana", "site_id": site.id}, source="rest"
        )
        with pytest.raises(Conflict):
            service.update_location(catalog.admin(), site.id, {"active": False}, source="rest")
        service.update_location(catalog.admin(), building.id, {"active": False}, source="rest")
        with pytest.raises(Conflict):
            service.update_location(catalog.admin(), site.id, {"active": False}, source="rest")
        service.update_person(catalog.admin(), person.id, {"status": "inactive"}, source="rest")
        deactivated = service.update_location(
            catalog.admin(), site.id, {"active": False}, source="rest"
        )

    assert deactivated.active is False


def test_location_reactivation_requires_an_active_parent(catalog: Catalog) -> None:
    with directory(catalog) as service:
        site = make_site(service, catalog)
        building = make_child(service, catalog, "building", site.id, "Edificio A")
        service.update_location(catalog.admin(), building.id, {"active": False}, source="rest")
        service.update_location(catalog.admin(), site.id, {"active": False}, source="rest")
        history_before = service.history(
            catalog.admin(), entity="location", entity_id=building.id
        ).total
        with pytest.raises(ValidationFailed) as rejected:
            service.update_location(catalog.admin(), building.id, {"active": True}, source="rest")
        stored = service.get_location(catalog.admin(), building.id)
        parent = service.get_location(catalog.admin(), site.id)
        history_after = service.history(
            catalog.admin(), entity="location", entity_id=building.id
        ).total
        service.update_location(catalog.admin(), site.id, {"active": True}, source="rest")
        reactivated = service.update_location(
            catalog.admin(), building.id, {"active": True}, source="rest"
        )

    assert str(rejected.value) == "parentId must reference an active location"
    assert (stored.active, stored.parent_id) == (False, site.id)
    assert parent.active is False
    assert history_before == history_after == 2
    assert reactivated.active is True


def test_location_reactivation_uses_the_parent_from_the_patch(catalog: Catalog) -> None:
    with directory(catalog) as service:
        closed = make_site(service, catalog)
        active = make_site(service, catalog, "Sede Sur")
        building = make_child(service, catalog, "building", closed.id, "Edificio A")
        service.update_location(catalog.admin(), building.id, {"active": False}, source="rest")
        service.update_location(catalog.admin(), closed.id, {"active": False}, source="rest")
        reactivated = service.update_location(
            catalog.admin(),
            building.id,
            {"active": True, "parent_id": active.id},
            source="rest",
        )

    assert (reactivated.active, reactivated.parent_id) == (True, active.id)
    assert events(catalog)[-1]["action"] == "activated"
    assert events(catalog)[-1]["after"] == {"active": True, "parentId": active.id}


def test_location_listing_filters_by_level_parent_and_active(catalog: Catalog) -> None:
    with directory(catalog) as service:
        site = make_site(service, catalog)
        make_child(service, catalog, "building", site.id, "Edificio A")
        archived = make_child(service, catalog, "building", site.id, "Edificio B")
        service.update_location(catalog.admin(), archived.id, {"active": False}, source="rest")
        buildings = service.list_locations(catalog.admin(), level="building")
        active = service.list_locations(catalog.admin(), parent_id=site.id, active=True)
        sites = service.list_locations(catalog.admin(), level="site", limit=1)

    assert [item.name for item in buildings.items] == ["Edificio A", "Edificio B"]
    assert buildings.total == 2
    assert [item.name for item in active.items] == ["Edificio A"]
    assert (sites.total, len(sites.items)) == (1, 1)


def test_location_tree_is_depth_and_node_bounded(catalog: Catalog) -> None:
    with directory(catalog) as service:
        site = make_site(service, catalog)
        first = make_child(service, catalog, "building", site.id, "Edificio A")
        make_child(service, catalog, "building", site.id, "Edificio B")
        floor = make_child(service, catalog, "floor", first.id, "Piso 1")
        make_child(service, catalog, "floor", first.id, "Piso 2")
        make_child(service, catalog, "room_zone", floor.id, "Sala 1")
        make_child(service, catalog, "room_zone", floor.id, "Sala 2")

        shallow = service.location_tree(catalog.admin(), root_id=site.id, depth=2)
        full = service.location_tree(catalog.admin(), root_id=site.id, depth=MAX_TREE_DEPTH)
        capped = service.location_tree(
            catalog.admin(), root_id=site.id, depth=MAX_TREE_DEPTH, max_nodes=4
        )
        forest = service.location_tree(catalog.admin(), depth=1)
        with pytest.raises(ValidationFailed):
            service.location_tree(catalog.admin(), depth=MAX_TREE_DEPTH + 1)
        with pytest.raises(ValidationFailed):
            service.location_tree(catalog.admin(), max_nodes=MAX_TREE_NODES + 1)
        with pytest.raises(NotFound):
            service.location_tree(catalog.admin(), root_id="0f8c5f1e-0000-4000-8000-000000000000")

    assert shallow.node_count == 3
    assert [child.location.name for child in shallow.roots[0].children] == [
        "Edificio A",
        "Edificio B",
    ]
    assert shallow.roots[0].children[0].children == ()
    assert (full.node_count, full.depth, full.truncated) == (7, MAX_TREE_DEPTH, False)
    assert (capped.node_count, capped.truncated) == (4, True)
    assert (forest.node_count, len(forest.roots)) == (1, 1)


# -------------------------------------------------------------------- events
def test_events_record_source_actor_and_effective_timestamp(catalog: Catalog) -> None:
    effective = datetime(2026, 2, 1, 8, 30, tzinfo=UTC)
    with directory(catalog) as service:
        person = service.create_person(
            catalog.admin(),
            {"name": "Julia Ocampos"},
            source="agent",
            effective_at=effective,
            notes="Alta por asistente",
        )
        service.update_person(
            catalog.admin(),
            person.id,
            {"job_title": "Técnica"},
            source="mcp",
            reason="Cargo confirmado",
            effective_at=effective + timedelta(days=1),
        )
        with pytest.raises(ValidationFailed):
            service.update_person(
                catalog.admin(), person.id, {"name": "Julia O."}, source="whatsapp"
            )
        with pytest.raises(ValidationFailed):
            service.update_person(
                catalog.admin(),
                person.id,
                {"name": "Julia O."},
                effective_at=datetime(2026, 2, 2, 8, 30),
            )

    with directory(catalog) as service:
        page = service.history(
            catalog.admin(), entity="person", entity_id=person.id, limit=10, offset=0
        )

    newest, created = page.items[0], page.items[1]
    assert (newest.action, newest.source, newest.actor_username) == ("updated", "mcp", "ana.admin")
    assert (created.action, created.source, created.actor_username) == (
        "created",
        "agent",
        "ana.admin",
    )
    assert created.effective_at == effective
    assert created.recorded_at > effective
    assert (created.notes, created.reason) == ("Alta por asistente", None)
    assert (newest.reason, newest.notes) == ("Cargo confirmado", None)
    assert newest.effective_at == effective + timedelta(days=1)
    assert newest.before == {"jobTitle": None}
    assert newest.after == {"jobTitle": "Técnica"}


def test_history_is_bounded_and_ordered_newest_first(catalog: Catalog) -> None:
    with directory(catalog) as service:
        person = service.create_person(catalog.admin(), {"name": "Kevin Paredes"}, source="rest")
        service.update_person(catalog.admin(), person.id, {"job_title": "Analista"}, source="rest")
        service.update_person(
            catalog.admin(), person.id, {"contact_phone": "+595 981 000 111"}, source="rest"
        )
        page = service.history(
            catalog.admin(), entity="person", entity_id=person.id, limit=2, offset=0
        )
        older = service.history(
            catalog.admin(), entity="person", entity_id=person.id, limit=1, offset=2
        )
        with pytest.raises(ValidationFailed):
            service.history(catalog.admin(), entity="asset", entity_id=person.id)
        with pytest.raises(NotFound):
            service.history(
                catalog.admin(),
                entity="person",
                entity_id="0f8c5f1e-0000-4000-8000-000000000000",
            )

    assert page.total == 3
    assert [item.action for item in page.items] == ["updated", "updated"]
    assert page.items[0].after == {"contactPhone": "+595 981 000 111"}
    assert [item.action for item in older.items] == ["created"]


# -------------------------------------------------------------- authorization
def test_reader_permission_is_denied_and_leaves_no_directory_row_or_event(
    catalog: Catalog,
) -> None:
    catalog.add_user(*READER)
    with directory(catalog) as service:
        reader = catalog.principal(READER[0])
        with pytest.raises(PermissionDenied):
            service.create_person(reader, {"name": "Sin Permiso"}, source="rest")
        with pytest.raises(PermissionDenied):
            service.create_department(reader, {"name": "Sin Permiso"}, source="rest")
        with pytest.raises(PermissionDenied):
            service.create_location(reader, {"level": "site", "name": "Sin Permiso"})

    assert rows(catalog, "directory_people") == 0
    assert rows(catalog, "directory_departments") == 0
    assert rows(catalog, "directory_locations") == 0
    assert events(catalog) == []
    assert [item["outcome"] for item in audit(catalog, "people.create")] == ["denied"]
    assert [item["outcome"] for item in audit(catalog, "config.departments")] == ["denied"]
    assert [item["outcome"] for item in audit(catalog, "config.sites")] == ["denied"]


def test_failed_terminal_audit_rolls_back_business_rows_and_events(
    catalog: Catalog, monkeypatch: pytest.MonkeyPatch
) -> None:
    def explode(*args: Any, **kwargs: Any) -> None:
        raise RuntimeError("terminal audit unavailable")

    monkeypatch.setattr(IdentityService, "record_operation", explode)
    with directory(catalog) as service:
        with pytest.raises(RuntimeError):
            service.create_person(catalog.admin(), {"name": "Rollback Total"}, source="rest")
        with pytest.raises(RuntimeError):
            service.create_location(catalog.admin(), {"level": "site", "name": "Sede Fantasma"})

    assert rows(catalog, "directory_people") == 0
    assert rows(catalog, "directory_locations") == 0
    assert events(catalog) == []
