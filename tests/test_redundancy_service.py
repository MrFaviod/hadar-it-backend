"""Redundancy groups: shares, roles, membership replacement, history and purge guards."""

from __future__ import annotations

import threading
from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime
from typing import Any

import pytest
from itsm.config import Settings
from itsm.identity.service import (
    Conflict,
    IdentityService,
    NotFound,
    PermissionDenied,
    ValidationFailed,
)
from itsm.inventory.service import InventoryService
from itsm.redundancy.service import MAX_MEMBERS, RedundancyService
from itsm.relationships.service import RelationshipService
from sqlalchemy import text
from tests.inventory_support import (
    OPERATOR,
    READER,
    Catalog,
    asset_values,
    prepare,
)

SettingsFactory = Callable[..., Settings]

EFFECTIVE = datetime(2026, 6, 1, 12, 0, tzinfo=UTC)

GROUP_KEYS = {
    "id",
    "name",
    "description",
    "mode",
    "active",
    "createdAt",
    "updatedAt",
    "memberCount",
    "members",
}
MEMBER_KEYS = {"assetId", "name", "quickCode", "archived", "role", "share", "host"}


@pytest.fixture
def catalog(settings_factory: SettingsFactory) -> Catalog:
    return prepare(settings_factory)


def create_asset(catalog: Catalog, **overrides: Any) -> Any:
    with catalog.session() as session:
        return InventoryService(session, catalog.settings).create(
            catalog.admin(), asset_values(**overrides)
        )


def host_assets(catalog: Catalog, child_id: str, host_id: str) -> None:
    with catalog.session() as session:
        RelationshipService(session, catalog.settings, source="internal").create(
            catalog.admin(),
            source_id=child_id,
            target_id=host_id,
            type_key="hosted_in",
            reason="inventario de hosting",
        )


def create_group(
    catalog: Catalog,
    *,
    principal: Any = None,
    source: str = "internal",
    **values: Any,
) -> Any:
    with catalog.session() as session:
        service = RedundancyService(session, catalog.settings, source=source)
        return service.create(principal or catalog.admin(), **values)


def update_group(
    catalog: Catalog,
    group_id: str,
    *,
    principal: Any = None,
    source: str = "internal",
    **values: Any,
) -> Any:
    with catalog.session() as session:
        service = RedundancyService(session, catalog.settings, source=source)
        return service.update(principal or catalog.admin(), group_id, **values)


def read_group(catalog: Catalog, group_id: str, *, principal: Any = None) -> Any:
    with catalog.session() as session:
        service = RedundancyService(session, catalog.settings)
        return service.get(principal or catalog.admin(), group_id)


def list_groups(catalog: Catalog, *, principal: Any = None, **values: Any) -> Any:
    with catalog.session() as session:
        service = RedundancyService(session, catalog.settings)
        return service.list(principal or catalog.admin(), **values)


def history(catalog: Catalog, asset_id: str) -> list[Any]:
    with catalog.session() as session:
        page = InventoryService(session, catalog.settings).history(catalog.admin(), asset_id)
        return list(page.items)


def scalar(catalog: Catalog, statement: str) -> Any:
    with catalog.engine.connect() as connection:
        return connection.execute(text(statement)).scalar_one()


def counters(catalog: Catalog) -> dict[str, int]:
    names = (
        "redundancy_groups",
        "redundancy_group_members",
        "assets",
        "asset_history",
        "identity_audit_events",
    )
    return {name: int(scalar(catalog, f"SELECT COUNT(*) FROM {name}")) for name in names}


def members(*pairs: tuple[Any, Any]) -> list[dict[str, Any]]:
    return [{"asset_id": asset.id, "share": share} for asset, share in pairs]


def primary_backup(primary: Any, *backups: Any) -> list[dict[str, Any]]:
    entries = [{"asset_id": primary.id, "role": "primary"}]
    entries.extend({"asset_id": asset.id, "role": "backup"} for asset in backups)
    return entries


# ------------------------------------------------------------------ active/active
def test_active_active_group_roundtrips_40_60_across_two_hosts(catalog: Catalog) -> None:
    host_one = create_asset(catalog, quick_code="RG-H1", name="Host Perimetral 1")
    host_two = create_asset(catalog, quick_code="RG-H2", name="Host Perimetral 2")
    vm_one = create_asset(catalog, quick_code="RG-V1", name="Portal replica 1")
    vm_two = create_asset(catalog, quick_code="RG-V2", name="Portal replica 2")
    host_assets(catalog, vm_one.id, host_one.id)
    host_assets(catalog, vm_two.id, host_two.id)

    view = create_group(
        catalog,
        name="Portal web",
        description="Balanceo AB 40/60 entre dos réplicas",
        mode="active_active",
        members=members((vm_one, "40"), (vm_two, "60")),
    )
    payload = view.as_payload()

    assert set(payload) == GROUP_KEYS
    assert payload["mode"] == "active_active"
    assert payload["active"] is True
    assert payload["memberCount"] == 2
    assert payload["description"] == "Balanceo AB 40/60 entre dos réplicas"
    by_asset = {member["assetId"]: member for member in payload["members"]}
    assert {asset_id: member["share"] for asset_id, member in by_asset.items()} == {
        vm_one.id: "40",
        vm_two.id: "60",
    }
    assert by_asset[vm_one.id]["host"] == {"id": host_one.id, "name": "Host Perimetral 1"}
    assert by_asset[vm_two.id]["host"] == {"id": host_two.id, "name": "Host Perimetral 2"}
    for member in payload["members"]:
        assert set(member) == MEMBER_KEYS
        assert member["role"] is None
        assert member["archived"] is False

    stored = read_group(catalog, payload["id"]).as_payload()
    assert stored == payload


def test_member_without_hosting_relation_reports_no_host(catalog: Catalog) -> None:
    first = create_asset(catalog, quick_code="RG-N1")
    second = create_asset(catalog, quick_code="RG-N2")

    payload = create_group(
        catalog,
        name="Sin hosting",
        mode="active_active",
        members=members((first, "50"), (second, "50")),
    ).as_payload()

    assert all(member["host"] is None for member in payload["members"])


def test_two_decimal_thirds_are_valid_and_canonical(catalog: Catalog) -> None:
    nodes = [create_asset(catalog, quick_code=f"RG-T{index}") for index in range(3)]

    payload = create_group(
        catalog,
        name="Tres réplicas",
        mode="active_active",
        members=members((nodes[0], "33.33"), (nodes[1], "33.33"), (nodes[2], "33.34")),
    ).as_payload()

    assert sorted(member["share"] for member in payload["members"]) == [
        "33.33",
        "33.33",
        "33.34",
    ]


def test_trailing_zero_share_is_stored_in_canonical_form(catalog: Catalog) -> None:
    first = create_asset(catalog, quick_code="RG-C1")
    second = create_asset(catalog, quick_code="RG-C2")

    payload = create_group(
        catalog,
        name="Canónico",
        mode="active_active",
        members=members((first, "40.0"), (second, "60.00")),
    ).as_payload()

    assert sorted(member["share"] for member in payload["members"]) == ["40", "60"]


@pytest.mark.parametrize(
    "bad_share",
    [
        "-0.01",
        "100.01",
        "33.333",
        "abc",
        "  ",
        True,
        False,
        float("nan"),
        float("inf"),
        float("-inf"),
        None,
    ],
)
def test_invalid_traffic_share_leaves_stored_state_unchanged(
    catalog: Catalog, bad_share: Any
) -> None:
    first = create_asset(catalog, quick_code="RG-I1")
    second = create_asset(catalog, quick_code="RG-I2")
    before = counters(catalog)

    with pytest.raises(ValidationFailed):
        create_group(
            catalog,
            name="Inválido",
            mode="active_active",
            members=[
                {"asset_id": first.id, "share": bad_share},
                {"asset_id": second.id, "share": "60"},
            ],
        )

    assert counters(catalog) == before


def test_traffic_shares_must_total_exactly_hundred(catalog: Catalog) -> None:
    first = create_asset(catalog, quick_code="RG-S1")
    second = create_asset(catalog, quick_code="RG-S2")
    before = counters(catalog)

    with pytest.raises(ValidationFailed, match="total exactly 100"):
        create_group(
            catalog,
            name="Suma inválida",
            mode="active_active",
            members=members((first, "40"), (second, "61")),
        )

    assert counters(catalog) == before


# ------------------------------------------------------------------ active/passive
def test_active_passive_keeps_one_primary_and_backups_without_shares(catalog: Catalog) -> None:
    primary = create_asset(catalog, quick_code="RG-P1")
    backup = create_asset(catalog, quick_code="RG-P2")

    payload = create_group(
        catalog,
        name="Base de datos",
        mode="active_passive",
        members=primary_backup(primary, backup),
    ).as_payload()

    assert payload["mode"] == "active_passive"
    by_asset = {member["assetId"]: member for member in payload["members"]}
    assert by_asset[primary.id]["role"] == "primary"
    assert by_asset[backup.id]["role"] == "backup"
    assert by_asset[primary.id]["share"] is None
    assert by_asset[backup.id]["share"] is None
    assert payload["members"][0]["role"] == "primary"


def test_active_passive_rejects_share_and_wrong_roles(catalog: Catalog) -> None:
    primary = create_asset(catalog, quick_code="RG-P3")
    backup = create_asset(catalog, quick_code="RG-P4")
    before = counters(catalog)

    cases = (
        [
            {"asset_id": primary.id, "role": "primary", "share": "50"},
            {"asset_id": backup.id, "role": "backup", "share": "50"},
        ],
        [
            {"asset_id": primary.id, "role": "primary"},
            {"asset_id": backup.id, "role": "primary"},
        ],
        [
            {"asset_id": primary.id, "role": "backup"},
            {"asset_id": backup.id, "role": "backup"},
        ],
        [
            {"asset_id": primary.id, "role": "leader"},
            {"asset_id": backup.id, "role": "backup"},
        ],
        [
            {"asset_id": primary.id, "role": "primary"},
            {"asset_id": backup.id, "role": "backup", "share": "100"},
        ],
    )
    for case in cases:
        with pytest.raises(ValidationFailed):
            create_group(
                catalog,
                name="Rol inválido",
                mode="active_passive",
                members=case,
            )
    assert counters(catalog) == before


def test_active_passive_requires_a_backup(catalog: Catalog) -> None:
    primary = create_asset(catalog, quick_code="RG-P5")
    backup = create_asset(catalog, quick_code="RG-P6")

    with pytest.raises(ValidationFailed, match="exactly one primary"):
        create_group(
            catalog,
            name="Sin respaldo",
            mode="active_passive",
            members=[
                {"asset_id": primary.id, "role": "backup"},
                {"asset_id": backup.id, "role": "backup"},
            ],
        )


# ------------------------------------------------------------------ membership rules
def test_duplicate_unknown_and_oversized_membership_is_rejected_before_writing(
    catalog: Catalog,
) -> None:
    first = create_asset(catalog, quick_code="RG-D1")
    second = create_asset(catalog, quick_code="RG-D2")
    before = counters(catalog)

    with pytest.raises(ValidationFailed, match="duplicate"):
        create_group(
            catalog,
            name="Duplicado",
            mode="active_active",
            members=members((first, "40"), (first, "60")),
        )
    with pytest.raises(NotFound):
        create_group(
            catalog,
            name="Desconocido",
            mode="active_active",
            members=[
                {"asset_id": "00000000-0000-4000-8000-000000000000", "share": "40"},
                {"asset_id": second.id, "share": "60"},
            ],
        )
    with pytest.raises(NotFound):
        create_group(
            catalog,
            name="Malformado",
            mode="active_active",
            members=[
                {"asset_id": "not-a-uuid", "share": "40"},
                {"asset_id": second.id, "share": "60"},
            ],
        )

    too_many = [
        {"asset_id": create_asset(catalog, quick_code=f"RG-M{index}").id, "share": "0"}
        for index in range(MAX_MEMBERS + 1)
    ]
    before_oversized = counters(catalog)
    with pytest.raises(ValidationFailed, match="at most"):
        create_group(catalog, name="Enorme", mode="active_active", members=too_many)
    assert counters(catalog) == before_oversized

    assert (
        int(scalar(catalog, "SELECT COUNT(*) FROM redundancy_groups"))
        == before["redundancy_groups"]
    )


def test_single_member_group_is_rejected(catalog: Catalog) -> None:
    only = create_asset(catalog, quick_code="RG-ONE")
    before = counters(catalog)

    with pytest.raises(ValidationFailed, match="at least two"):
        create_group(
            catalog,
            name="Una sola",
            mode="active_active",
            members=[{"asset_id": only.id, "share": "100"}],
        )

    assert counters(catalog) == before


def test_mode_change_requires_the_complete_member_list(catalog: Catalog) -> None:
    primary = create_asset(catalog, quick_code="RG-MC1")
    backup = create_asset(catalog, quick_code="RG-MC2")
    payload = create_group(
        catalog,
        name="Cambio de modo",
        mode="active_active",
        members=members((primary, "40"), (backup, "60")),
    ).as_payload()
    before = counters(catalog)

    with pytest.raises(ValidationFailed, match="complete member list"):
        update_group(catalog, payload["id"], mode="active_passive")

    assert counters(catalog) == before
    assert read_group(catalog, payload["id"]).as_payload()["mode"] == "active_active"


def test_archived_members_are_refused_by_active_groups_but_allowed_for_cleanup(
    catalog: Catalog,
) -> None:
    first = create_asset(catalog, quick_code="RG-A1")
    second = create_asset(catalog, quick_code="RG-A2")
    third = create_asset(catalog, quick_code="RG-A3")
    retired = create_asset(catalog, quick_code="RG-A0")
    archive(catalog, retired.id, reason="baja previa al grupo")

    before = counters(catalog)
    with pytest.raises(Conflict, match="active redundancy group"):
        create_group(
            catalog,
            name="Archivado nuevo",
            mode="active_active",
            members=members((retired, "40"), (third, "60")),
        )
    assert counters(catalog) == before

    payload = create_group(
        catalog,
        name="Archivado",
        mode="active_active",
        members=members((first, "40"), (second, "60")),
    ).as_payload()
    deactivate(catalog, payload["id"])
    archive(catalog, first.id, reason="baja de la réplica")

    before = snapshot(catalog, payload["id"], [first.id, second.id])
    with pytest.raises(Conflict, match="active redundancy group"):
        update_group(
            catalog,
            payload["id"],
            members=[
                {"asset_id": first.id, "share": "40"},
                {"asset_id": second.id, "share": "60"},
            ],
            active=True,
        )
    assert snapshot(catalog, payload["id"], [first.id, second.id]) == before


def test_deactivated_group_allows_cleanup_and_reactivation(catalog: Catalog) -> None:
    first = create_asset(catalog, quick_code="RG-R1")
    second = create_asset(catalog, quick_code="RG-R2")
    third = create_asset(catalog, quick_code="RG-R3")
    payload = create_group(
        catalog,
        name="Limpieza",
        mode="active_active",
        members=members((first, "40"), (second, "60")),
    ).as_payload()

    with catalog.session() as session:
        inactive = RedundancyService(session, catalog.settings).deactivate(
            catalog.admin(), payload["id"], reason="ventana de mantenimiento"
        )
    assert inactive.as_payload()["active"] is False

    with catalog.session() as session:
        InventoryService(session, catalog.settings).archive(
            catalog.admin(), first.id, reason="réplica retirada"
        )
    cleaned = update_group(
        catalog,
        payload["id"],
        members=[{"asset_id": second.id, "share": "100"}],
        reason="limpieza de réplica archivada",
    ).as_payload()
    assert cleaned["memberCount"] == 1
    assert cleaned["members"][0]["archived"] is False

    with pytest.raises(ValidationFailed, match="at least two"):
        update_group(catalog, payload["id"], active=True)

    restored = update_group(
        catalog,
        payload["id"],
        members=members((second, "60"), (third, "40")),
        active=True,
    ).as_payload()
    assert restored["active"] is True
    assert restored["memberCount"] == 2


# ------------------------------------------------------------------ permissions
def test_reader_can_read_but_every_mutation_is_denied_and_audited(catalog: Catalog) -> None:
    first = create_asset(catalog, quick_code="RG-X1")
    second = create_asset(catalog, quick_code="RG-X2")
    payload = create_group(
        catalog,
        name="Lectura",
        mode="active_active",
        members=members((first, "40"), (second, "60")),
    ).as_payload()
    reader = catalog.add_user(*READER)
    operator = catalog.add_user(*OPERATOR)
    before = counters(catalog)

    assert read_group(catalog, payload["id"], principal=reader).as_payload()["id"] == payload["id"]
    assert list_groups(catalog, principal=reader).total == 1

    with pytest.raises(PermissionDenied):
        update_group(catalog, payload["id"], principal=reader, name="Robado")
    with pytest.raises(PermissionDenied):
        create_group(
            catalog,
            principal=reader,
            name="Intruso",
            mode="active_active",
            members=members((first, "40"), (second, "60")),
        )
    with catalog.session() as session, pytest.raises(PermissionDenied):
        RedundancyService(session, catalog.settings).deactivate(
            reader, payload["id"], reason="sin permiso"
        )

    after = counters(catalog)
    assert after["redundancy_groups"] == before["redundancy_groups"]
    assert after["redundancy_group_members"] == before["redundancy_group_members"]
    assert after["asset_history"] == before["asset_history"]
    assert after["identity_audit_events"] > before["identity_audit_events"]

    updated = update_group(catalog, payload["id"], principal=operator, name="Operador")
    assert updated.as_payload()["name"] == "Operador"


def test_group_source_is_trusted_and_cannot_come_from_a_caller(catalog: Catalog) -> None:
    with catalog.session() as session, pytest.raises(ValidationFailed):
        RedundancyService(session, catalog.settings, source="client")


# ------------------------------------------------------------------ history and audit
def test_mutations_write_one_audit_and_structured_member_history(catalog: Catalog) -> None:
    first = create_asset(catalog, quick_code="RG-H1")
    second = create_asset(catalog, quick_code="RG-H2")
    before_audit = len(catalog.audit("redundancy.group_created"))

    payload = create_group(
        catalog,
        source="agent",
        name="Con historial",
        mode="active_active",
        members=members((first, "40"), (second, "60")),
        reason="alta del grupo de redundancia",
        notes="balanceo 40/60 configurado",
        effective_at=EFFECTIVE,
    ).as_payload()

    events = catalog.audit("redundancy.group_created")
    assert len(events) == before_audit + 1
    assert events[-1]["resource"] == f"redundancy-group:{payload['id']}"
    assert events[-1]["outcome"] == "success"

    rows = history(catalog, first.id)
    created = [row for row in rows if row.action == "redundancy_group_created"]
    assert len(created) == 1
    entry = created[0]
    assert entry.source == "agent"
    assert entry.entity_type == "redundancy_group"
    assert entry.entity_id == payload["id"]
    assert entry.effective_at == EFFECTIVE
    assert entry.reason == "alta del grupo de redundancia"
    assert entry.notes == "balanceo 40/60 configurado"
    change = entry.structured_payload()["changes"]["redundancyGroup"]
    assert change["old"] is None
    assert change["new"] == {
        "groupId": payload["id"],
        "name": "Con historial",
        "mode": "active_active",
        "active": True,
        "role": None,
        "share": "40",
    }

    updated = update_group(
        catalog,
        payload["id"],
        members=members((first, "30"), (second, "70")),
        reason="rebalanceo de tráfico",
    ).as_payload()
    assert updated["id"] == payload["id"]
    latest = [
        row
        for row in history(catalog, second.id)
        if row.action == "redundancy_group_updated" and row.entity_id == payload["id"]
    ][-1]
    change = latest.structured_payload()["changes"]["redundancyGroup"]
    assert change["old"]["share"] == "60"
    assert change["new"]["share"] == "70"
    assert len(catalog.audit("redundancy.group_updated")) == 1

    with catalog.session() as session:
        RedundancyService(session, catalog.settings).deactivate(
            catalog.admin(), payload["id"], reason="fin del servicio"
        )
    deactivated = [
        row
        for row in history(catalog, first.id)
        if row.action == "redundancy_group_deactivated" and row.entity_id == payload["id"]
    ]
    assert len(deactivated) == 1
    assert (
        deactivated[0].structured_payload()["changes"]["redundancyGroup"]["new"]["active"] is False
    )
    assert len(catalog.audit("redundancy.group_deactivated")) == 1


def test_replacement_records_removal_history_for_the_dropped_member(catalog: Catalog) -> None:
    first = create_asset(catalog, quick_code="RG-E1")
    second = create_asset(catalog, quick_code="RG-E2")
    third = create_asset(catalog, quick_code="RG-E3")
    payload = create_group(
        catalog,
        name="Reemplazo",
        mode="active_active",
        members=members((first, "40"), (second, "60")),
    ).as_payload()

    update_group(
        catalog,
        payload["id"],
        members=members((second, "60"), (third, "40")),
        reason="reemplazo de réplica",
    )

    removed = [
        row
        for row in history(catalog, first.id)
        if row.action == "redundancy_group_updated" and row.entity_id == payload["id"]
    ]
    assert len(removed) == 1
    change = removed[0].structured_payload()["changes"]["redundancyGroup"]
    assert change["new"] is None
    assert change["old"]["share"] == "40"
    # The retained member must not receive a no-op history event.
    retained = [
        row
        for row in history(catalog, second.id)
        if row.action == "redundancy_group_updated" and row.entity_id == payload["id"]
    ]
    assert len(retained) == 0


# ------------------------------------------------------------------ atomic replacement
def test_member_replacement_is_atomic_and_keeps_group_identity(catalog: Catalog) -> None:
    first = create_asset(catalog, quick_code="RG-U1")
    second = create_asset(catalog, quick_code="RG-U2")
    third = create_asset(catalog, quick_code="RG-U3")
    created = create_group(
        catalog,
        name="Atomicidad",
        mode="active_active",
        members=members((first, "40"), (second, "60")),
    ).as_payload()

    replaced = update_group(
        catalog,
        created["id"],
        name="Atomicidad renombrada",
        members=members((second, "30"), (third, "70")),
        reason="reconfiguración",
    ).as_payload()

    assert replaced["id"] == created["id"]
    assert replaced["createdAt"] == created["createdAt"]
    assert replaced["name"] == "Atomicidad renombrada"
    assert {member["assetId"] for member in replaced["members"]} == {second.id, third.id}
    assert int(scalar(catalog, "SELECT COUNT(*) FROM redundancy_groups")) == 1
    assert int(scalar(catalog, "SELECT COUNT(*) FROM redundancy_group_members")) == 2

    failed_before = counters(catalog)
    with pytest.raises(NotFound):
        update_group(
            catalog,
            created["id"],
            members=[
                {"asset_id": second.id, "share": "50"},
                {"asset_id": "00000000-0000-4000-8000-000000000000", "share": "50"},
            ],
        )
    assert counters(catalog) == failed_before
    after = read_group(catalog, created["id"]).as_payload()
    assert {member["assetId"] for member in after["members"]} == {second.id, third.id}


def test_update_and_deactivate_keep_hosting_edges_and_asset_identity(catalog: Catalog) -> None:
    host_one = create_asset(catalog, quick_code="RG-KH1")
    host_two = create_asset(catalog, quick_code="RG-KH2")
    first = create_asset(catalog, quick_code="RG-K1")
    second = create_asset(catalog, quick_code="RG-K2")
    host_assets(catalog, first.id, host_one.id)
    host_assets(catalog, second.id, host_two.id)
    payload = create_group(
        catalog,
        name="Hosting estable",
        mode="active_active",
        members=members((first, "40"), (second, "60")),
    ).as_payload()

    def placement() -> tuple[list[tuple[str, str]], list[tuple[str, str]]]:
        with catalog.engine.connect() as connection:
            edges = [
                (row[0], row[1])
                for row in connection.execute(
                    text(
                        "SELECT source_id, target_id FROM relationships "
                        "WHERE type_key = 'hosted_in' ORDER BY source_id"
                    )
                )
            ]
            assets = [
                (row[0], row[1])
                for row in connection.execute(text("SELECT id, quick_code FROM assets ORDER BY id"))
            ]
        return edges, assets

    before = placement()
    update_group(
        catalog,
        payload["id"],
        members=members((first, "25"), (second, "75")),
        reason="ajuste de tráfico",
    )
    with catalog.session() as session:
        RedundancyService(session, catalog.settings).deactivate(
            catalog.admin(), payload["id"], reason="ventana"
        )

    assert placement() == before
    assert read_group(catalog, payload["id"]).as_payload()["members"][0]["host"] is not None


def test_permanent_purge_is_blocked_until_membership_is_cleaned_up(catalog: Catalog) -> None:
    first = create_asset(catalog, quick_code="RG-G1")
    second = create_asset(catalog, quick_code="RG-G2")
    payload = create_group(
        catalog,
        name="Purga",
        mode="active_active",
        members=members((first, "40"), (second, "60")),
    ).as_payload()
    before = counters(catalog)

    with catalog.session() as session, pytest.raises(Conflict):
        InventoryService(session, catalog.settings).purge(catalog.admin(), first.id, confirm=True)
    assert counters(catalog) == before

    with catalog.session() as session:
        RedundancyService(session, catalog.settings).deactivate(
            catalog.admin(), payload["id"], reason="fin del servicio"
        )
    update_group(
        catalog,
        payload["id"],
        members=[{"asset_id": second.id, "share": "100"}],
        reason="retiro de la réplica",
    )
    with catalog.session() as session:
        InventoryService(session, catalog.settings).purge(catalog.admin(), first.id, confirm=True)
    assert int(scalar(catalog, "SELECT COUNT(*) FROM redundancy_group_members")) == 1
    assert int(scalar(catalog, "SELECT COUNT(*) FROM redundancy_groups")) == 1


# ------------------------------------------------------------------ concurrency/rollback
def test_concurrent_member_replacements_are_serialized(catalog: Catalog) -> None:
    assets = [create_asset(catalog, quick_code=f"RG-CC{index}") for index in range(4)]
    payload = create_group(
        catalog,
        name="Concurrente",
        mode="active_active",
        members=members((assets[0], "40"), (assets[1], "60")),
    ).as_payload()
    barrier = threading.Barrier(2)
    failures: list[BaseException] = []
    expected = [
        {assets[0].id: "50", assets[1].id: "50"},
        {assets[2].id: "50", assets[3].id: "50"},
    ]

    def replace(left: Any, right: Any) -> None:
        session = catalog.factory()()
        try:
            service = RedundancyService(session, catalog.settings, source="internal")
            barrier.wait(timeout=10)
            service.update(
                catalog.admin(),
                payload["id"],
                members=members((left, "50"), (right, "50")),
                reason="reemplazo concurrente",
            )
        except BaseException as exc:  # recorded for the assertion below
            failures.append(exc)
        finally:
            session.close()

    threads = [
        threading.Thread(target=replace, args=(assets[0], assets[1])),
        threading.Thread(target=replace, args=(assets[2], assets[3])),
    ]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(timeout=30)
    catalog.engine.dispose()

    assert failures == []
    final = read_group(catalog, payload["id"]).as_payload()
    assert {member["assetId"]: member["share"] for member in final["members"]} in expected
    assert final["memberCount"] == 2


def test_history_failure_rolls_back_membership_and_releases_the_lock(
    catalog: Catalog, monkeypatch: pytest.MonkeyPatch
) -> None:
    first = create_asset(catalog, quick_code="RG-F1")
    second = create_asset(catalog, quick_code="RG-F2")
    payload = create_group(
        catalog,
        name="Fallo de historial",
        mode="active_active",
        members=members((first, "40"), (second, "60")),
    ).as_payload()
    before = counters(catalog)

    def explode(*_args: Any, **_kwargs: Any) -> None:
        raise RuntimeError("forced history failure")

    with monkeypatch.context() as patch:
        patch.setattr(InventoryService, "_record_history", explode)
        with pytest.raises(RuntimeError, match="forced history failure"):
            update_group(
                catalog,
                payload["id"],
                members=members((first, "10"), (second, "90")),
                reason="fallo forzado",
            )

    assert counters(catalog) == before
    unchanged = read_group(catalog, payload["id"]).as_payload()
    assert {member["share"] for member in unchanged["members"]} == {"40", "60"}

    recovered = update_group(
        catalog,
        payload["id"],
        members=members((first, "20"), (second, "80")),
        reason="recuperación",
    ).as_payload()
    assert {member["share"] for member in recovered["members"]} == {"20", "80"}


def test_audit_failure_rolls_back_group_creation_and_releases_the_lock(
    catalog: Catalog, monkeypatch: pytest.MonkeyPatch
) -> None:
    first = create_asset(catalog, quick_code="RG-F3")
    second = create_asset(catalog, quick_code="RG-F4")
    before = counters(catalog)

    def explode(*_args: Any, **_kwargs: Any) -> None:
        raise RuntimeError("forced audit failure")

    with monkeypatch.context() as patch:
        patch.setattr(IdentityService, "record_operation", explode)
        with pytest.raises(RuntimeError, match="forced audit failure"):
            create_group(
                catalog,
                name="Fallo de auditoría",
                mode="active_active",
                members=members((first, "40"), (second, "60")),
            )

    assert counters(catalog) == before

    created = create_group(
        catalog,
        name="Recuperado",
        mode="active_active",
        members=members((first, "50"), (second, "50")),
    ).as_payload()
    assert created["memberCount"] == 2


# ------------------------------------------------------------------ reads
def test_list_is_bounded_filters_and_never_materializes_the_inventory(catalog: Catalog) -> None:
    first = create_asset(catalog, quick_code="RG-L1")
    second = create_asset(catalog, quick_code="RG-L2")
    created = create_group(
        catalog,
        name="Frontend productivo",
        mode="active_active",
        members=members((first, "40"), (second, "60")),
    ).as_payload()
    create_group(
        catalog,
        name="Respaldo contable",
        mode="active_passive",
        members=primary_backup(first, second),
    )

    page = list_groups(catalog)
    assert page.total == 2
    assert page.limit == 50
    assert len(page.items) == 2
    assert [group.name for group in page.items] == sorted(group.name for group in page.items)
    assert all(set(group.as_payload()) == GROUP_KEYS for group in page.items)

    filtered = list_groups(catalog, query="frontend")
    assert filtered.total == 1
    assert filtered.items[0].id == created["id"]
    assert list_groups(catalog, mode="active_passive").total == 1
    assert list_groups(catalog, active=False).total == 0

    with pytest.raises(ValidationFailed):
        list_groups(catalog, limit=0)
    with pytest.raises(ValidationFailed):
        list_groups(catalog, limit=201)
    with pytest.raises(ValidationFailed):
        list_groups(catalog, offset=-1)
    with pytest.raises(ValidationFailed):
        list_groups(catalog, mode="active")


def test_missing_group_and_invalid_id_are_reported_as_not_found(catalog: Catalog) -> None:
    with pytest.raises(NotFound):
        read_group(catalog, "00000000-0000-4000-8000-000000000000")
    with pytest.raises(NotFound):
        read_group(catalog, "not-a-uuid")
    with pytest.raises(NotFound):
        update_group(catalog, "not-a-uuid", name="x")


# ---------------------------------------------------- archive transition guard
def snapshot(catalog: Catalog, group_id: str, asset_ids: list[str]) -> dict[str, Any]:
    """Capture every observable the refused archive must leave untouched."""
    with catalog.session() as session:
        inventory = InventoryService(session, catalog.settings)
        assets = {
            asset_id: inventory.get(catalog.admin(), asset_id).as_payload()
            for asset_id in asset_ids
        }
    return {
        "group": read_group(catalog, group_id).as_payload(),
        "assets": assets,
        "history": {
            asset_id: [entry.as_payload() for entry in history(catalog, asset_id)]
            for asset_id in asset_ids
        },
        "counters": counters(catalog),
        "audit": len(catalog.audit()),
        "tombstones": int(scalar(catalog, "SELECT COUNT(*) FROM asset_tombstones")),
    }


def archive(catalog: Catalog, asset_id: str, *, reason: str = "baja de réplica") -> Any:
    with catalog.session() as session:
        return InventoryService(session, catalog.settings).archive(
            catalog.admin(), asset_id, reason=reason
        )


def deactivate(catalog: Catalog, group_id: str, *, reason: str = "mantenimiento") -> Any:
    with catalog.session() as session:
        return RedundancyService(session, catalog.settings).deactivate(
            catalog.admin(), group_id, reason=reason
        )


def member_specs(mode: str, first: Any, second: Any) -> list[dict[str, Any]]:
    if mode == "active_passive":
        return primary_backup(first, second)
    return members((first, "40"), (second, "60"))


@pytest.mark.parametrize(
    ("mode", "first_code", "second_code"),
    [
        ("active_active", "RG-X1", "RG-X2"),
        ("active_passive", "RG-X3", "RG-X4"),
    ],
)
def test_archiving_a_member_of_an_active_group_is_refused(
    catalog: Catalog, mode: str, first_code: str, second_code: str
) -> None:
    """The archived flag is not a back door into an invalid active membership."""
    first = create_asset(catalog, quick_code=first_code)
    second = create_asset(catalog, quick_code=second_code)
    payload = create_group(
        catalog,
        name=f"Guardia {mode}",
        mode=mode,
        members=member_specs(mode, first, second),
    ).as_payload()
    before = snapshot(catalog, payload["id"], [first.id, second.id])

    with catalog.session() as session, pytest.raises(Conflict, match="active redundancy group"):
        InventoryService(session, catalog.settings).archive(
            catalog.admin(), first.id, reason="baja de la réplica"
        )

    assert snapshot(catalog, payload["id"], [first.id, second.id]) == before
    stored = read_group(catalog, payload["id"]).as_payload()
    assert stored["active"] is True
    assert {member["assetId"]: member["archived"] for member in stored["members"]} == {
        first.id: False,
        second.id: False,
    }
    actions = [entry.action for entry in history(catalog, first.id)]
    assert actions == ["created", "redundancy_group_created"]
    assert "archived" not in actions


def test_any_active_group_blocks_archiving_until_every_membership_is_clean(
    catalog: Catalog,
) -> None:
    shared = create_asset(catalog, quick_code="RG-M1")
    other_one = create_asset(catalog, quick_code="RG-M2")
    other_two = create_asset(catalog, quick_code="RG-M3")
    first_group = create_group(
        catalog,
        name="Grupo uno",
        mode="active_active",
        members=members((shared, "50"), (other_one, "50")),
    ).as_payload()
    second_group = create_group(
        catalog,
        name="Grupo dos",
        mode="active_active",
        members=members((shared, "50"), (other_two, "50")),
    ).as_payload()

    with pytest.raises(Conflict, match="active redundancy group"):
        archive(catalog, shared.id)

    deactivate(catalog, first_group["id"])
    before = snapshot(catalog, first_group["id"], [shared.id])
    with pytest.raises(Conflict, match="active redundancy group"):
        archive(catalog, shared.id)
    assert snapshot(catalog, first_group["id"], [shared.id]) == before

    deactivate(catalog, second_group["id"])
    assert archive(catalog, shared.id).archived is True


def test_inactive_group_may_retain_an_archived_member_but_never_reactivates_it(
    catalog: Catalog,
) -> None:
    first = create_asset(catalog, quick_code="RG-C1")
    second = create_asset(catalog, quick_code="RG-C2")
    payload = create_group(
        catalog,
        name="Limpieza archivada",
        mode="active_active",
        members=members((first, "40"), (second, "60")),
    ).as_payload()

    assert deactivate(catalog, payload["id"]).as_payload()["active"] is False
    assert archive(catalog, first.id).archived is True

    kept = read_group(catalog, payload["id"]).as_payload()
    assert kept["active"] is False
    assert {member["assetId"]: member["archived"] for member in kept["members"]} == {
        first.id: True,
        second.id: False,
    }

    before = snapshot(catalog, payload["id"], [first.id, second.id])
    with pytest.raises(Conflict, match="active redundancy group"):
        update_group(catalog, payload["id"], active=True)
    with pytest.raises(Conflict, match="active redundancy group"):
        update_group(
            catalog,
            payload["id"],
            members=[
                {"asset_id": first.id, "share": "40"},
                {"asset_id": second.id, "share": "60"},
            ],
            active=True,
        )
    assert snapshot(catalog, payload["id"], [first.id, second.id]) == before

    cleaned = update_group(catalog, payload["id"], members=members((second, "100"))).as_payload()
    assert cleaned["memberCount"] == 1
    assert cleaned["members"][0]["assetId"] == second.id


def test_activation_and_archive_order_keeps_the_invariant_and_releases_the_lock(
    catalog: Catalog,
) -> None:
    activate_first_one = create_asset(catalog, quick_code="RG-O1")
    activate_first_two = create_asset(catalog, quick_code="RG-O2")
    activate_first = create_group(
        catalog,
        name="Orden activar primero",
        mode="active_active",
        members=members((activate_first_one, "40"), (activate_first_two, "60")),
    ).as_payload()
    deactivate(catalog, activate_first["id"])
    update_group(catalog, activate_first["id"], active=True)

    with pytest.raises(Conflict, match="active redundancy group"):
        archive(catalog, activate_first_one.id)

    stored = read_group(catalog, activate_first["id"]).as_payload()
    assert stored["active"] is True
    assert all(member["archived"] is False for member in stored["members"])

    archive_first_one = create_asset(catalog, quick_code="RG-O3")
    archive_first_two = create_asset(catalog, quick_code="RG-O4")
    archive_first = create_group(
        catalog,
        name="Orden archivar primero",
        mode="active_active",
        members=members((archive_first_one, "40"), (archive_first_two, "60")),
    ).as_payload()
    deactivate(catalog, archive_first["id"])
    assert archive(catalog, archive_first_one.id).archived is True

    with pytest.raises(Conflict, match="active redundancy group"):
        update_group(catalog, archive_first["id"], active=True)

    stored = read_group(catalog, archive_first["id"]).as_payload()
    assert stored["active"] is False
    assert {member["assetId"]: member["archived"] for member in stored["members"]}[
        archive_first_one.id
    ] is True

    released = update_group(
        catalog,
        archive_first["id"],
        members=members((archive_first_two, "100")),
    ).as_payload()
    assert released["memberCount"] == 1


def test_concurrent_activation_and_archive_cannot_break_the_invariant(
    catalog: Catalog,
) -> None:
    first = create_asset(catalog, quick_code="RG-P1")
    second = create_asset(catalog, quick_code="RG-P2")
    payload = create_group(
        catalog,
        name="Carrera",
        mode="active_active",
        members=members((first, "40"), (second, "60")),
    ).as_payload()
    deactivate(catalog, payload["id"])

    barrier = threading.Barrier(2)
    outcomes: list[str] = []

    def activate() -> None:
        barrier.wait()
        with catalog.session() as session:
            try:
                RedundancyService(session, catalog.settings).update(
                    catalog.admin(), payload["id"], active=True
                )
            except Conflict:
                outcomes.append("activation-refused")
            else:
                outcomes.append("activated")

    def retire() -> None:
        barrier.wait()
        with catalog.session() as session:
            try:
                InventoryService(session, catalog.settings).archive(
                    catalog.admin(), first.id, reason="baja concurrente"
                )
            except Conflict:
                outcomes.append("archive-refused")
            else:
                outcomes.append("archived")

    with ThreadPoolExecutor(max_workers=2) as pool:
        futures = [pool.submit(activate), pool.submit(retire)]
        for future in futures:
            future.result()
    catalog.engine.dispose()

    assert len(outcomes) == 2
    assert set(outcomes) <= {"activated", "activation-refused", "archived", "archive-refused"}
    stored = read_group(catalog, payload["id"]).as_payload()
    archived_ids = [member["assetId"] for member in stored["members"] if member["archived"]]
    assert not (stored["active"] is True and archived_ids)
    assert outcomes.count("archived") == len(archived_ids)

    if stored["active"] is True:
        released = deactivate(catalog, payload["id"], reason="cierre").as_payload()
        assert released["active"] is False
    else:
        released = update_group(
            catalog, payload["id"], members=[{"asset_id": second.id, "share": "100"}]
        ).as_payload()
        assert released["memberCount"] == 1
