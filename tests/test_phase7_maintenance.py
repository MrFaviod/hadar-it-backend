"""Phase 7 preventive maintenance: recurrence, templates/overrides, lifecycle and queries."""

from __future__ import annotations

import hashlib
from collections.abc import Callable, Iterator
from contextlib import asynccontextmanager, contextmanager
from datetime import date
from typing import Any

import pytest
from fastapi import APIRouter, FastAPI
from fastapi.testclient import TestClient
from itsm.config import Settings
from itsm.database import create_engine_from_settings, create_session_factory
from itsm.directory.service import DirectoryService
from itsm.identity.api import create_identity_router, install_error_handlers
from itsm.identity.clock import utcnow
from itsm.identity.service import (
    Conflict,
    IdentityService,
    PermissionDenied,
    ValidationFailed,
)
from itsm.inventory.catalog import InventoryCatalog
from itsm.inventory.service import InventoryService
from itsm.maintenance.api import create_maintenance_router
from itsm.maintenance.service import MaintenanceService, add_months
from sqlalchemy import inspect, text
from tests.conftest import ADMIN_PASSWORD, ADMIN_USERNAME
from tests.inventory_support import (
    MACHINE_PASSWORD,
    OPERATOR,
    READER,
    Catalog,
    asset_values,
    prepare,
    sign_in_as,
)

SettingsFactory = Callable[..., Settings]


@pytest.fixture
def catalog(settings_factory: SettingsFactory) -> Catalog:
    return prepare(settings_factory)


@asynccontextmanager
async def _lifespan(app: FastAPI, settings: Settings) -> Iterator[None]:
    """Minimal app state so the maintenance router can be exercised before integration."""
    engine = create_engine_from_settings(settings)
    app.state.settings = settings
    app.state.engine = engine
    app.state.session_factory = create_session_factory(engine)
    try:
        yield
    finally:
        engine.dispose()


@pytest.fixture
def api(catalog: Catalog) -> Iterator[tuple[TestClient, dict[str, str]]]:
    app = FastAPI(lifespan=lambda app: _lifespan(app, catalog.settings))
    install_error_handlers(app)
    api = APIRouter(prefix=catalog.settings.api_prefix)
    api.include_router(create_identity_router())
    api.include_router(create_maintenance_router())
    app.include_router(api)
    with TestClient(app) as client:
        auth = sign_in_as(client, catalog.settings, ADMIN_USERNAME, ADMIN_PASSWORD)
        yield client, auth


@contextmanager
def maintenance(catalog: Catalog) -> Iterator[MaintenanceService]:
    with catalog.session() as session:
        yield MaintenanceService(session, catalog.settings, source="rest")


def create_asset(catalog: Catalog, quick_code: str, **overrides: Any) -> Any:
    values = asset_values(quick_code=quick_code, name=f"Equipo {quick_code}", **overrides)
    with catalog.session() as session:
        return InventoryService(session, catalog.settings).create(catalog.admin(), values)


def create_plan(catalog: Catalog, **kwargs: Any) -> Any:
    with maintenance(catalog) as service:
        return service.create_plan(catalog.admin(), **kwargs)


def list_plans(catalog: Catalog, **kwargs: Any) -> Any:
    with maintenance(catalog) as service:
        return service.list_plans(catalog.admin(), **kwargs)


def plan_count(catalog: Catalog) -> int:
    with catalog.engine.connect() as connection:
        return int(connection.execute(text("SELECT COUNT(*) FROM maintenance_plans")).scalar_one())


def template_count(catalog: Catalog) -> int:
    with catalog.engine.connect() as connection:
        return int(
            connection.execute(text("SELECT COUNT(*) FROM maintenance_templates")).scalar_one()
        )


def plan_actions(catalog: Catalog, asset_id: str) -> list[str]:
    with catalog.session() as session:
        page = InventoryService(session, catalog.settings).history(
            catalog.admin(), asset_id, limit=200
        )
    return [entry.action for entry in page.items if entry.entity_type == "maintenance_plan"]


def test_add_months_clamps_calendar_month_end_and_leap_year() -> None:
    assert add_months(date(2024, 1, 10), 6) == date(2024, 7, 10)
    assert add_months(date(2024, 1, 31), 1) == date(2024, 2, 29)
    assert add_months(date(2023, 8, 31), 6) == date(2024, 2, 29)
    assert add_months(date(2024, 2, 29), 12) == date(2025, 2, 28)
    for invalid in (0, -1, 121):
        with pytest.raises(ValidationFailed):
            add_months(date(2024, 1, 10), invalid)


def test_completion_anchors_next_due_to_actual_completion_date(catalog: Catalog) -> None:
    asset = create_asset(catalog, "CAM-001")
    virtual = list_plans(catalog, asset_id=asset.id).items[0]
    assert virtual.persisted is False
    assert virtual.last_completed_on is None
    assert virtual.scheduled_on == asset.created_at.date()

    with maintenance(catalog) as service:
        completed = service.complete_plan(
            catalog.admin(), virtual.id, completed_on=date(2024, 1, 10)
        )
    assert completed.id == virtual.id
    assert completed.persisted is True
    assert completed.last_completed_on == date(2024, 1, 10)
    assert completed.due_on == date(2024, 7, 10)
    assert completed.status == "active"

    monthly = create_asset(catalog, "CAM-002")
    plan = create_plan(
        catalog,
        asset_id=monthly.id,
        maintenance_type="preventivo",
        interval_months=1,
        due_on=date(2024, 1, 31),
    )
    with maintenance(catalog) as service:
        completed = service.complete_plan(catalog.admin(), plan.id, completed_on=date(2024, 1, 31))
    assert completed.due_on == date(2024, 2, 29)
    assert completed.last_completed_on == date(2024, 1, 31)

    with maintenance(catalog) as service:
        fetched = service.get_plan(catalog.admin(), virtual.id)
    assert fetched.id == virtual.id
    assert fetched.due_on == date(2024, 7, 10)


def test_first_due_uses_scheduled_base_and_never_invents_completion(catalog: Catalog) -> None:
    asset = create_asset(catalog, "CAM-010")
    plans = list_plans(catalog, asset_id=asset.id)
    default_plan = plans.items[0]
    assert default_plan.last_completed_on is None
    assert default_plan.scheduled_on == asset.created_at.date()
    assert default_plan.due_on == add_months(asset.created_at.date(), default_plan.interval_months)

    imported = create_asset(catalog, "CAM-011")
    with maintenance(catalog) as service:
        explicit = service.create_plan(
            catalog.admin(),
            asset_id=imported.id,
            maintenance_type="limpieza",
            interval_months=6,
            last_completed_on=date(2024, 1, 10),
        )
    assert explicit.last_completed_on == date(2024, 1, 10)
    assert explicit.due_on == date(2024, 7, 10)
    assert explicit.scheduled_on == date(2024, 1, 10)


def test_virtual_defaults_follow_live_catalog_and_never_write_on_read(catalog: Catalog) -> None:
    asset = create_asset(catalog, "CAM-020", category="camaras")
    plans = list_plans(catalog, asset_id=asset.id)
    assert len(plans.items) == 1
    plan = plans.items[0]
    assert plan.maintenance_type == "preventivo"
    assert plan.interval_months == 6
    assert plan.tasks
    assert plan.persisted is False
    assert plan_count(catalog) == 0

    # A label is a legacy spelling of the same authoritative catalog id.
    labeled = create_asset(catalog, "CAM-021", category="Cámaras")
    assert list_plans(catalog, asset_id=labeled.id).items[0].interval_months == 6

    with maintenance(catalog) as service:
        templates = service.list_templates(catalog.admin())
    ids = {item.category for item in templates.items}
    assert {"computadoras", "servidores", "docker", "lxc", "contenedores", "camaras"} <= ids

    # Logical tasks for virtualized/container categories, not physical cleaning.
    with maintenance(catalog) as service:
        virtualized = [
            item
            for item in service.list_templates(catalog.admin(), limit=200).items
            if item.category in {"virtualizacion", "docker", "lxc", "contenedores"}
        ]
    assert virtualized
    for item in virtualized:
        assert all("limpiar" not in task.casefold() for task in item.tasks)
        assert any(
            "verificar" in task.casefold() or "revisar" in task.casefold() for task in item.tasks
        )

    # A future category added to the authoritative catalog inherits a usable default.
    with catalog.session() as session:
        InventoryCatalog(session, catalog.settings).put(
            catalog.admin(),
            "categories",
            "drones",
            {
                "id": "drones",
                "label": "Drones",
                "prefix": "DRN",
                "type": "Equipo",
                "icon": "box",
                "active": True,
                "fov": False,
                "quick": ["name", "type"],
                "advanced": ["serial"],
                "tech": [],
            },
        )
    future = create_asset(catalog, "DRN-001", category="drones")
    future_plan = list_plans(catalog, asset_id=future.id).items[0]
    assert future_plan.interval_months == 12
    assert future_plan.tasks
    assert plan_count(catalog) == 0


def test_templates_are_editable_and_asset_overrides_stay_isolated(catalog: Catalog) -> None:
    asset_a = create_asset(catalog, "CAM-030", category="camaras")
    asset_b = create_asset(catalog, "CAM-031", category="camaras")
    with maintenance(catalog) as service:
        default = next(
            item
            for item in service.list_templates(catalog.admin()).items
            if item.category == "camaras"
        )
        assert default.source == "default"
        edited = service.update_template(
            catalog.admin(),
            default.id,
            interval_months=4,
            tasks=["Revisar grabación", "Verificar firmware"],
        )
    assert edited.id == default.id
    assert edited.source == "stored"
    assert edited.interval_months == 4
    assert template_count(catalog) == 1

    assert list_plans(catalog, asset_id=asset_a.id).items[0].interval_months == 4
    assert list_plans(catalog, asset_id=asset_b.id).items[0].interval_months == 4

    override = create_plan(
        catalog,
        asset_id=asset_b.id,
        maintenance_type="preventivo",
        interval_months=2,
        tasks=["Excepción del activo"],
    )
    assert override.persisted is True
    assert plan_count(catalog) == 1

    with maintenance(catalog) as service:
        service.update_template(catalog.admin(), default.id, interval_months=5)
    assert list_plans(catalog, asset_id=asset_a.id).items[0].interval_months == 5
    assert list_plans(catalog, asset_id=asset_b.id).items[0].interval_months == 2
    assert list_plans(catalog, asset_id=asset_b.id).items[0].tasks == ["Excepción del activo"]

    with maintenance(catalog) as service:
        service.delete_template(catalog.admin(), edited.id)
    restored = next(
        item for item in service.list_templates(catalog.admin()).items if item.category == "camaras"
    )
    assert restored.source == "default"
    assert restored.interval_months == 6
    assert template_count(catalog) == 0
    assert list_plans(catalog, asset_id=asset_b.id).items[0].interval_months == 2


def test_complete_postpone_cancel_and_rejected_states_preserve_data(catalog: Catalog) -> None:
    today = utcnow().date()
    asset = create_asset(catalog, "SW-040", category="switches")
    plan = create_plan(
        catalog,
        asset_id=asset.id,
        maintenance_type="preventivo",
        due_on=today,
    )
    with maintenance(catalog) as service:
        postponed = service.postpone_plan(
            catalog.admin(),
            plan.id,
            due_on=today.fromordinal(today.toordinal() + 10),
            notes="Ventana",
        )
    assert postponed.status == "postponed"
    assert postponed.last_completed_on is None
    assert postponed.due_on > today

    with maintenance(catalog) as service:
        completed = service.complete_plan(
            catalog.admin(), plan.id, completed_on=today, notes="Hecho"
        )
    assert completed.status == "active"
    assert completed.last_completed_on == today
    assert completed.due_on == add_months(today, completed.interval_months)

    with maintenance(catalog) as service:
        cancelled = service.cancel_plan(catalog.admin(), plan.id, notes="Ya no aplica")
    assert cancelled.status == "cancelled"
    assert cancelled.due_on == completed.due_on
    assert cancelled.last_completed_on == today

    with catalog.session() as session:
        history_before = (
            InventoryService(session, catalog.settings)
            .history(catalog.admin(), asset.id, limit=200)
            .total
        )
    for operation in (
        lambda service: service.complete_plan(catalog.admin(), plan.id),
        lambda service: service.postpone_plan(
            catalog.admin(), plan.id, due_on=today.fromordinal(today.toordinal() + 30)
        ),
        lambda service: service.cancel_plan(catalog.admin(), plan.id),
    ):
        with maintenance(catalog) as service, pytest.raises(Conflict):
            operation(service)
    with maintenance(catalog) as service:
        stored = service.get_plan(catalog.admin(), plan.id)
    assert stored.status == "cancelled"
    assert stored.due_on == completed.due_on
    with catalog.session() as session:
        assert (
            InventoryService(session, catalog.settings)
            .history(catalog.admin(), asset.id, limit=200)
            .total
            == history_before
        )

    assert plan_actions(catalog, asset.id) == [
        "maintenance_plan_created",
        "maintenance_postponed",
        "maintenance_completed",
        "maintenance_cancelled",
    ]
    assert len(catalog.audit("maintenance.plan_completed")) == 1
    assert len(catalog.audit("maintenance.plan_cancelled")) == 1


def test_corrective_asset_changes_never_reset_the_preventive_cycle(catalog: Catalog) -> None:
    today = utcnow().date()
    asset = create_asset(catalog, "SW-050", category="switches")
    plan = create_plan(catalog, asset_id=asset.id, maintenance_type="preventivo")
    with maintenance(catalog) as service:
        completed = service.complete_plan(catalog.admin(), plan.id, completed_on=today)

    with catalog.session() as session:
        InventoryService(session, catalog.settings).update(
            catalog.admin(),
            asset.id,
            {"status": "maintenance", "description": "Trabajo correctivo registrado"},
        )
    with maintenance(catalog) as service:
        after = service.get_plan(catalog.admin(), plan.id)
    assert after.last_completed_on == completed.last_completed_on
    assert after.due_on == completed.due_on
    assert after.status == completed.status
    actions = plan_actions(catalog, asset.id)
    assert actions.count("maintenance_completed") == 1


def test_queries_filter_state_category_site_period_and_paginate(catalog: Catalog) -> None:
    today = utcnow().date()
    overdue = create_asset(catalog, "CAM-060", category="camaras", site="Example Site")
    upcoming = create_asset(catalog, "CAM-061", category="camaras", site="Central")
    other = create_asset(catalog, "SW-062", category="switches", site="Example Site")
    cancelled_asset = create_asset(catalog, "CAM-063", category="camaras", site="Central")

    create_plan(
        catalog,
        asset_id=overdue.id,
        maintenance_type="preventivo",
        due_on=today.fromordinal(today.toordinal() - 5),
    )
    create_plan(
        catalog,
        asset_id=upcoming.id,
        maintenance_type="preventivo",
        due_on=today.fromordinal(today.toordinal() + 10),
    )
    create_plan(
        catalog,
        asset_id=other.id,
        maintenance_type="preventivo",
        due_on=today.fromordinal(today.toordinal() - 1),
    )
    cancelled = create_plan(
        catalog,
        asset_id=cancelled_asset.id,
        maintenance_type="preventivo",
        due_on=today.fromordinal(today.toordinal() - 2),
    )
    with maintenance(catalog) as service:
        service.cancel_plan(catalog.admin(), cancelled.id)

    assert list_plans(catalog, state="overdue").total == 2
    assert list_plans(catalog, state="upcoming", upcoming_days=30).total == 1
    assert list_plans(catalog, state="pending").total == 3
    assert list_plans(catalog, status="cancelled").total == 1
    assert list_plans(catalog, category="camaras").total == 3
    assert list_plans(catalog, site="Example Site").total == 2
    assert (
        list_plans(catalog, due_from=today, due_to=today.fromordinal(today.toordinal() + 30)).total
        == 1
    )

    page = list_plans(catalog, state="pending", limit=1, offset=1)
    assert page.total == 3
    assert len(page.items) == 1
    with pytest.raises(ValidationFailed):
        list_plans(catalog, limit=201)


def test_http_contract_uses_camel_case_pages_and_error_envelope(
    api: tuple[TestClient, dict[str, str]], catalog: Catalog
) -> None:
    client, auth = api
    prefix = catalog.settings.api_prefix
    asset = create_asset(catalog, "CAM-070", category="camaras")
    plan = create_plan(catalog, asset_id=asset.id, maintenance_type="preventivo")

    response = client.get(f"{prefix}/maintenance/plans", headers=auth)
    assert response.status_code == 200
    body = response.json()
    assert set(body) == {"items", "total", "limit", "offset"}
    assert body["items"][0]["id"] == plan.id
    assert body["items"][0]["assetQuickCode"] == "CAM-070"
    assert body["items"][0]["maintenanceType"] == "preventivo"
    assert body["items"][0]["lastCompletedOn"] is None
    assert body["items"][0]["scheduledOn"] == asset.created_at.date().isoformat()

    completed = client.post(
        f"{prefix}/maintenance/plans/{plan.id}/complete",
        json={"completedOn": "2024-01-10"},
        headers=auth,
    )
    assert completed.status_code == 200
    assert completed.json()["dueOn"] == "2024-07-10"

    templates = client.get(f"{prefix}/maintenance/templates", headers=auth)
    assert templates.status_code == 200
    assert templates.json()["items"][0]["source"] == "default"

    invalid = client.get(f"{prefix}/maintenance/plans", params={"limit": 201}, headers=auth)
    assert invalid.status_code == 422
    assert invalid.json()["error"]["code"] == "validation_error"

    missing = client.post(
        f"{prefix}/maintenance/plans", json={"maintenanceType": "preventivo"}, headers=auth
    )
    assert missing.status_code == 422
    assert missing.json()["error"]["code"] == "validation_error"


def test_authorization_reuses_existing_permissions_and_denials_preserve_state(
    api: tuple[TestClient, dict[str, str]], catalog: Catalog
) -> None:
    client, _ = api
    prefix = catalog.settings.api_prefix
    asset = create_asset(catalog, "CAM-080", category="camaras")
    with catalog.session() as session:
        history_before = (
            InventoryService(session, catalog.settings)
            .history(catalog.admin(), asset.id, limit=200)
            .total
        )
    catalog.add_user(*READER)
    catalog.add_user(*OPERATOR)

    with maintenance(catalog) as service:
        assert service.list_plans(catalog.principal(READER[0])).total == 1
        with pytest.raises(PermissionDenied):
            service.list_templates(catalog.principal(READER[0]))
        with pytest.raises(PermissionDenied):
            service.create_plan(
                catalog.principal(READER[0]),
                asset_id=asset.id,
                maintenance_type="preventivo",
            )
        operator_plan = service.create_plan(
            catalog.principal(OPERATOR[0]),
            asset_id=asset.id,
            maintenance_type="preventivo",
            interval_months=3,
        )
        with pytest.raises(PermissionDenied):
            service.update_template(
                catalog.principal(OPERATOR[0]), operator_plan.id, interval_months=4
            )
    assert plan_count(catalog) == 1
    with catalog.session() as session:
        history_after = (
            InventoryService(session, catalog.settings)
            .history(catalog.admin(), asset.id, limit=200)
            .total
        )
    assert history_after == history_before + 1

    reader_auth = sign_in_as(client, catalog.settings, READER[0], MACHINE_PASSWORD)
    assert client.get(f"{prefix}/maintenance/plans", headers=reader_auth).status_code == 200
    forbidden = client.get(f"{prefix}/maintenance/templates", headers=reader_auth)
    assert forbidden.status_code == 403
    assert forbidden.json()["error"]["code"] == "forbidden"
    denied = client.post(
        f"{prefix}/maintenance/plans",
        json={"assetId": asset.id, "maintenanceType": "preventivo"},
        headers=reader_auth,
    )
    assert denied.status_code == 403
    assert plan_count(catalog) == 1


def _state_snapshot(catalog: Catalog) -> dict[str, Any]:
    """Hash every table except the expected denied-audit row."""
    snapshot: dict[str, Any] = {}
    with catalog.engine.connect() as connection:
        for name in inspect(catalog.engine).get_table_names():
            if name == "identity_audit_events":
                continue
            rows = connection.execute(text(f'SELECT * FROM "{name}" ORDER BY 1')).all()
            snapshot[name] = hashlib.sha256(repr(rows).encode()).hexdigest()
            snapshot[f"{name}#count"] = len(rows)
    return snapshot


@pytest.mark.parametrize(
    "kind", ["virtual_template", "stored_template", "virtual_plan", "stored_plan"]
)
def test_denied_responsible_person_lookup_cannot_commit_partial_changes(
    catalog: Catalog, kind: str
) -> None:
    admin = catalog.admin()
    with catalog.session() as session:
        person = DirectoryService(session, catalog.settings).create_person(
            admin, {"name": "Restricted responsible"}
        )
        asset = InventoryService(session, catalog.settings).create(admin, asset_values())
        role = IdentityService(session, catalog.settings).create_role(
            admin,
            name="No directory read",
            permissions=["assets.edit", "assets.view", "config.general"],
        )
    actor = catalog.add_user("limited", "Limited", role.id)

    with maintenance(catalog) as service:
        template = service.list_templates(admin, category="switches").items[0]
        plan = service.list_plans(admin, asset_id=asset.id).items[0]
        if kind == "stored_template":
            service.update_template(admin, template.id, interval_months=6)
        if kind == "stored_plan":
            service.update_plan(admin, plan.id, interval_months=6)

    before = _state_snapshot(catalog)
    audit_before = catalog.audit()
    with maintenance(catalog) as service, pytest.raises(PermissionDenied):
        if kind.endswith("template"):
            service.update_template(
                actor,
                template.id,
                interval_months=1,
                responsible_person_id=person.id,
            )
        else:
            service.update_plan(
                actor,
                plan.id,
                interval_months=1,
                responsible_person_id=person.id,
            )

    assert _state_snapshot(catalog) == before
    audit_after = catalog.audit()
    assert audit_after[: len(audit_before)] == audit_before
    assert audit_after[len(audit_before) :] == [
        {
            "actor": "limited",
            "action": "people.view",
            "resource": f"person:{person.id}",
            "outcome": "denied",
        }
    ]


def test_plan_identity_is_stable_across_materialization_and_template_edits(
    catalog: Catalog,
) -> None:
    asset = create_asset(catalog, "CAM-090", category="camaras")
    first = list_plans(catalog, asset_id=asset.id).items[0]
    second = list_plans(catalog, asset_id=asset.id).items[0]
    assert first.id == second.id
    assert first.persisted is False

    with maintenance(catalog) as service:
        completed = service.complete_plan(catalog.admin(), first.id)
    assert completed.id == first.id
    assert completed.persisted is True
    assert list_plans(catalog, asset_id=asset.id).items[0].id == first.id

    with maintenance(catalog) as service:
        default = next(
            item
            for item in service.list_templates(catalog.admin()).items
            if item.category == "camaras"
        )
        edited = service.update_template(catalog.admin(), default.id, interval_months=3)
    assert edited.id == default.id
    assert edited.source == "stored"


def create_person(catalog: Catalog, name: str) -> Any:
    with catalog.session() as session:
        return DirectoryService(session, catalog.settings).create_person(
            catalog.admin(), {"name": name}
        )


def test_owner_omitted_inherits_and_explicit_null_clears(catalog: Catalog) -> None:
    person = create_person(catalog, "Responsable preventivo")
    asset = create_asset(catalog, "CAM-100", category="camaras")
    with maintenance(catalog) as service:
        default = next(
            item
            for item in service.list_templates(catalog.admin()).items
            if item.category == "camaras"
        )
        service.update_template(catalog.admin(), default.id, responsible_person_id=person.id)
    inherited = list_plans(catalog, asset_id=asset.id).items[0]
    assert inherited.responsible_person_id == person.id
    assert inherited.responsible_label == "Responsable preventivo"

    with maintenance(catalog) as service:
        override = service.update_plan(catalog.admin(), inherited.id, interval_months=4)
    assert override.responsible_person_id == person.id

    with maintenance(catalog) as service:
        cleared = service.update_plan(catalog.admin(), inherited.id, responsible_person_id=None)
    assert cleared.responsible_person_id is None
    assert cleared.responsible_label is None
    with maintenance(catalog) as service:
        template = next(
            item
            for item in service.list_templates(catalog.admin()).items
            if item.category == "camaras"
        )
    assert template.responsible_person_id == person.id


def test_cancelled_plan_stays_cancelled_after_template_edits(catalog: Catalog) -> None:
    asset = create_asset(catalog, "CAM-110", category="camaras")
    plan = create_plan(
        catalog,
        asset_id=asset.id,
        maintenance_type="preventivo",
        interval_months=6,
        due_on=date(2026, 12, 1),
    )
    with maintenance(catalog) as service:
        cancelled = service.cancel_plan(catalog.admin(), plan.id, notes="Fuera de servicio")
        default = next(
            item
            for item in service.list_templates(catalog.admin()).items
            if item.category == "camaras"
        )
        service.update_template(catalog.admin(), default.id, interval_months=2)
        reloaded = service.get_plan(catalog.admin(), plan.id)
    assert cancelled.status == "cancelled"
    assert reloaded.status == "cancelled"
    assert reloaded.due_on == date(2026, 12, 1)
    assert reloaded.interval_months == 6
    assert list_plans(catalog, asset_id=asset.id).items[0].status == "cancelled"


def test_repeated_completion_reanchors_from_the_actual_day(catalog: Catalog) -> None:
    leap = create_asset(catalog, "SW-120", category="switches")
    leap_plan = create_plan(
        catalog,
        asset_id=leap.id,
        maintenance_type="preventivo",
        interval_months=1,
        due_on=date(2024, 1, 31),
    )
    with maintenance(catalog) as service:
        first = service.complete_plan(catalog.admin(), leap_plan.id, completed_on=date(2024, 1, 31))
        second = service.complete_plan(
            catalog.admin(), leap_plan.id, completed_on=date(2024, 2, 29)
        )
    assert first.due_on == date(2024, 2, 29)
    assert second.due_on == date(2024, 3, 29)

    plain = create_asset(catalog, "SW-121", category="switches")
    plain_plan = create_plan(
        catalog,
        asset_id=plain.id,
        maintenance_type="preventivo",
        interval_months=1,
        due_on=date(2023, 1, 31),
    )
    with maintenance(catalog) as service:
        first = service.complete_plan(
            catalog.admin(), plain_plan.id, completed_on=date(2023, 1, 31)
        )
        second = service.complete_plan(
            catalog.admin(), plain_plan.id, completed_on=date(2023, 2, 28)
        )
    assert first.due_on == date(2023, 2, 28)
    assert second.due_on == date(2023, 3, 28)
