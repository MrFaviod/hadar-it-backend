"""Relationship service: typed directed edges, containment, hosts, graphs and audit."""

from __future__ import annotations

import itertools
from collections.abc import Callable
from datetime import UTC, datetime
from typing import Any

import pytest
from itsm.config import Settings
from itsm.identity.service import (
    Conflict,
    NotFound,
    PermissionDenied,
    ValidationFailed,
)
from itsm.inventory.service import InventoryService
from itsm.relationships import service as relationship_module
from itsm.relationships.service import (
    MAX_GRAPH_DEPTH,
    RelationshipService,
)
from sqlalchemy import text
from tests.inventory_support import OPERATOR, READER, Catalog, asset_values, prepare

SettingsFactory = Callable[..., Settings]

EFFECTIVE = datetime(2026, 5, 12, 14, 30, tzinfo=UTC)


@pytest.fixture
def catalog(settings_factory: SettingsFactory) -> Catalog:
    return prepare(settings_factory)


def create_asset(catalog: Catalog, **overrides: Any) -> Any:
    with catalog.session() as session:
        return InventoryService(session, catalog.settings).create(
            catalog.admin(), asset_values(**overrides)
        )


def history(catalog: Catalog, asset_id: str) -> list[Any]:
    with catalog.session() as session:
        page = InventoryService(session, catalog.settings).history(catalog.admin(), asset_id)
        return list(page.items)


def scalar(catalog: Catalog, statement: str) -> Any:
    with catalog.engine.connect() as connection:
        return connection.execute(text(statement)).scalar_one()


def edge_count(catalog: Catalog) -> int:
    return int(scalar(catalog, "SELECT COUNT(*) FROM relationships"))


def history_count(catalog: Catalog) -> int:
    return int(scalar(catalog, "SELECT COUNT(*) FROM asset_history"))


def max_sequence(catalog: Catalog) -> int:
    return int(scalar(catalog, "SELECT COALESCE(MAX(sequence), 0) FROM asset_history"))


def write(catalog: Catalog, operation: Callable[[RelationshipService], Any]) -> Any:
    session = catalog.factory()()
    try:
        service = RelationshipService(session, catalog.settings, source="internal")
        result = operation(service)
        session.commit()
        return result
    finally:
        session.close()


def read(catalog: Catalog, operation: Callable[[RelationshipService], Any]) -> Any:
    session = catalog.factory()()
    try:
        service = RelationshipService(session, catalog.settings, source="internal")
        return operation(service)
    finally:
        session.close()


# --------------------------------------------------------------------- types
def test_default_relationship_types_match_the_migrated_snapshot(catalog: Catalog) -> None:
    types = read(catalog, lambda service: service.list_types(catalog.admin()))

    assert [
        (item.key, item.forward_label, item.inverse_label, item.containment) for item in types
    ] == [
        ("associated_with", "Asociado con", "Asociado con", False),
        ("connected_to", "Conectado a", "Conectado desde", False),
        ("depends_on", "Depende de", "Requerido por", False),
        ("hosted_in", "Alojado en", "Aloja", True),
        ("installed_in", "Instalado en", "Contiene", True),
        ("protected_by", "Protegido por", "Protege a", False),
    ]


def test_reader_can_read_types_but_cannot_configure_them(catalog: Catalog) -> None:
    catalog.add_user(*READER)
    reader = catalog.principal(READER[0])

    types = read(catalog, lambda service: service.list_types(reader))
    assert len(types) == 6

    with pytest.raises(PermissionDenied):
        write(
            catalog,
            lambda service: service.create_type(
                reader,
                "runs_on",
                forward_label="Ejecuta en",
                inverse_label="Ejecuta",
            ),
        )


def test_custom_type_is_stable_and_deactivation_is_non_destructive(catalog: Catalog) -> None:
    created = write(
        catalog,
        lambda service: service.create_type(
            catalog.admin(),
            "runs_on",
            forward_label="Ejecuta en",
            inverse_label="Ejecuta",
        ),
    )
    assert created.key == "runs_on"
    assert created.active is True

    source = create_asset(catalog, quick_code="SRC-001")
    target = create_asset(catalog, quick_code="TGT-001")
    edge = write(
        catalog,
        lambda service: service.create(
            catalog.admin(), source_id=source.id, target_id=target.id, type_key="runs_on"
        ),
    )

    updated = write(
        catalog,
        lambda service: service.update_type(
            catalog.admin(),
            "runs_on",
            forward_label="Se ejecuta en",
            inverse_label="Ejecuta procesos de",
        ),
    )
    assert updated.key == "runs_on"
    assert updated.forward_label == "Se ejecuta en"

    deactivated = write(
        catalog,
        lambda service: service.update_type(catalog.admin(), "runs_on", active=False),
    )
    assert deactivated.active is False

    visible = read(catalog, lambda service: service.list(catalog.admin(), asset_id=source.id))
    assert visible.total == 1
    assert visible.items[0].id == edge.id
    assert visible.items[0].active is False

    with pytest.raises(Conflict):
        write(
            catalog,
            lambda service: service.create(
                catalog.admin(),
                source_id=source.id,
                target_id=target.id,
                type_key="runs_on",
            ),
        )

    write(catalog, lambda service: service.update_type(catalog.admin(), "runs_on", active=True))
    other = create_asset(catalog, quick_code="TGT-002")
    reactivated = write(
        catalog,
        lambda service: service.create(
            catalog.admin(),
            source_id=source.id,
            target_id=other.id,
            type_key="runs_on",
        ),
    )
    assert reactivated.type_key == "runs_on"


def test_type_keys_are_unique(catalog: Catalog) -> None:
    write(
        catalog,
        lambda service: service.create_type(
            catalog.admin(), "sits_on", forward_label="Se apoya en", inverse_label="Sostiene"
        ),
    )
    with pytest.raises(Conflict):
        write(
            catalog,
            lambda service: service.create_type(
                catalog.admin(), "sits_on", forward_label="Otro", inverse_label="Otro"
            ),
        )

    types = read(
        catalog, lambda service: service.list_types(catalog.admin(), include_inactive=True)
    )
    assert [item.key for item in types].count("sits_on") == 1


# ----------------------------------------------------------------- relations
def test_directed_relation_uses_forward_and_inverse_labels_per_asset(catalog: Catalog) -> None:
    source = create_asset(catalog, quick_code="SW-001")
    target = create_asset(catalog, quick_code="FW-001")
    edge = write(
        catalog,
        lambda service: service.create(
            catalog.admin(), source_id=source.id, target_id=target.id, type_key="connected_to"
        ),
    )

    outgoing = read(
        catalog, lambda service: service.list(catalog.admin(), asset_id=source.id)
    ).items[0]
    incoming = read(
        catalog, lambda service: service.list(catalog.admin(), asset_id=target.id)
    ).items[0]

    assert (edge.source_id, edge.target_id) == (source.id, target.id)
    assert (outgoing.direction, outgoing.label) == ("outgoing", "Conectado a")
    assert (incoming.direction, incoming.label) == ("incoming", "Conectado desde")
    assert incoming.id == edge.id


def test_duplicate_same_source_target_type_is_rejected_without_writes(catalog: Catalog) -> None:
    source = create_asset(catalog, quick_code="DUP-001")
    target = create_asset(catalog, quick_code="DUP-002")
    write(
        catalog,
        lambda service: service.create(
            catalog.admin(), source_id=source.id, target_id=target.id, type_key="connected_to"
        ),
    )
    edges_before = edge_count(catalog)
    history_before = history_count(catalog)
    sequence_before = max_sequence(catalog)

    with pytest.raises(Conflict):
        write(
            catalog,
            lambda service: service.create(
                catalog.admin(), source_id=source.id, target_id=target.id, type_key="connected_to"
            ),
        )

    assert edge_count(catalog) == edges_before
    assert history_count(catalog) == history_before
    assert max_sequence(catalog) == sequence_before


def test_self_relation_and_missing_endpoint_are_rejected(catalog: Catalog) -> None:
    source = create_asset(catalog, quick_code="SLF-001")

    with pytest.raises(ValidationFailed):
        write(
            catalog,
            lambda service: service.create(
                catalog.admin(), source_id=source.id, target_id=source.id, type_key="connected_to"
            ),
        )

    with pytest.raises(NotFound):
        write(
            catalog,
            lambda service: service.create(
                catalog.admin(),
                source_id=source.id,
                target_id="00000000-0000-0000-0000-000000000000",
                type_key="connected_to",
            ),
        )

    assert edge_count(catalog) == 0


def test_general_graph_cycles_and_multiple_relation_types_are_allowed(catalog: Catalog) -> None:
    first = create_asset(catalog, quick_code="CYC-001")
    second = create_asset(catalog, quick_code="CYC-002")

    for type_key in ("connected_to", "depends_on"):
        write(
            catalog,
            lambda service, type_key=type_key: service.create(
                catalog.admin(), source_id=first.id, target_id=second.id, type_key=type_key
            ),
        )
        write(
            catalog,
            lambda service, type_key=type_key: service.create(
                catalog.admin(), source_id=second.id, target_id=first.id, type_key=type_key
            ),
        )

    assert edge_count(catalog) == 4


def test_containment_self_and_ancestor_cycles_are_rejected_without_writes(
    catalog: Catalog,
) -> None:
    parent = create_asset(catalog, quick_code="CON-001")
    child = create_asset(catalog, quick_code="CON-002")
    write(
        catalog,
        lambda service: service.create(
            catalog.admin(), source_id=child.id, target_id=parent.id, type_key="installed_in"
        ),
    )
    edges_before = edge_count(catalog)
    history_before = history_count(catalog)
    sequence_before = max_sequence(catalog)

    with pytest.raises(Conflict):
        write(
            catalog,
            lambda service: service.create(
                catalog.admin(), source_id=parent.id, target_id=child.id, type_key="installed_in"
            ),
        )
    with pytest.raises(ValidationFailed):
        write(
            catalog,
            lambda service: service.create(
                catalog.admin(), source_id=parent.id, target_id=parent.id, type_key="hosted_in"
            ),
        )

    assert edge_count(catalog) == edges_before
    assert history_count(catalog) == history_before
    assert max_sequence(catalog) == sequence_before


def test_mixed_containment_edges_are_checked_as_one_hierarchy(catalog: Catalog) -> None:
    room = create_asset(catalog, quick_code="MIX-001")
    host = create_asset(catalog, quick_code="MIX-002")
    virtual = create_asset(catalog, quick_code="MIX-003")

    write(
        catalog,
        lambda service: service.create(
            catalog.admin(), source_id=virtual.id, target_id=host.id, type_key="hosted_in"
        ),
    )
    write(
        catalog,
        lambda service: service.create(
            catalog.admin(), source_id=host.id, target_id=room.id, type_key="installed_in"
        ),
    )

    with pytest.raises(Conflict):
        write(
            catalog,
            lambda service: service.create(
                catalog.admin(), source_id=room.id, target_id=virtual.id, type_key="installed_in"
            ),
        )

    assert edge_count(catalog) == 2


def test_non_containment_edges_do_not_create_containment_cycles(catalog: Catalog) -> None:
    parent = create_asset(catalog, quick_code="NCN-001")
    child = create_asset(catalog, quick_code="NCN-002")

    write(
        catalog,
        lambda service: service.create(
            catalog.admin(), source_id=child.id, target_id=parent.id, type_key="hosted_in"
        ),
    )
    write(
        catalog,
        lambda service: service.create(
            catalog.admin(), source_id=parent.id, target_id=child.id, type_key="depends_on"
        ),
    )

    assert edge_count(catalog) == 2


def test_archived_endpoints_keep_visible_edges_but_cannot_gain_new_ones(
    catalog: Catalog,
) -> None:
    source = create_asset(catalog, quick_code="ARC-001")
    archived = create_asset(catalog, quick_code="ARC-002")
    other = create_asset(catalog, quick_code="ARC-003")
    edge = write(
        catalog,
        lambda service: service.create(
            catalog.admin(), source_id=source.id, target_id=archived.id, type_key="connected_to"
        ),
    )
    with catalog.session() as session:
        InventoryService(session, catalog.settings).archive(
            catalog.admin(), archived.id, reason="retirado"
        )

    visible = read(catalog, lambda service: service.list(catalog.admin(), asset_id=archived.id))
    assert [item.id for item in visible.items] == [edge.id]

    with pytest.raises(Conflict):
        write(
            catalog,
            lambda service: service.create(
                catalog.admin(), source_id=source.id, target_id=archived.id, type_key="depends_on"
            ),
        )
    with pytest.raises(Conflict):
        write(
            catalog,
            lambda service: service.create(
                catalog.admin(), source_id=archived.id, target_id=other.id, type_key="depends_on"
            ),
        )

    write(catalog, lambda service: service.remove(catalog.admin(), edge.id))
    assert edge_count(catalog) == 0


def test_purge_of_a_related_asset_is_rejected_before_any_write(catalog: Catalog) -> None:
    source = create_asset(catalog, quick_code="PRG-001")
    target = create_asset(catalog, quick_code="PRG-002")
    write(
        catalog,
        lambda service: service.create(
            catalog.admin(), source_id=source.id, target_id=target.id, type_key="connected_to"
        ),
    )
    history_before = history_count(catalog)

    with catalog.session() as session, pytest.raises(Conflict):
        InventoryService(session, catalog.settings).purge(
            catalog.admin(), source.id, confirm=True, reason="limpieza"
        )

    assert catalog.asset_count() == 2
    assert edge_count(catalog) == 1
    assert history_count(catalog) == history_before
    assert int(scalar(catalog, "SELECT COUNT(*) FROM asset_tombstones")) == 0


def test_one_host_per_hosted_in_child_but_other_edges_allow_multiplicity(
    catalog: Catalog,
) -> None:
    host_one = create_asset(catalog, quick_code="HST-001")
    host_two = create_asset(catalog, quick_code="HST-002")
    virtual = create_asset(catalog, quick_code="HST-003")

    write(
        catalog,
        lambda service: service.create(
            catalog.admin(), source_id=virtual.id, target_id=host_one.id, type_key="hosted_in"
        ),
    )
    with pytest.raises(Conflict):
        write(
            catalog,
            lambda service: service.create(
                catalog.admin(), source_id=virtual.id, target_id=host_two.id, type_key="hosted_in"
            ),
        )

    for host in (host_one, host_two):
        write(
            catalog,
            lambda service, host=host: service.create(
                catalog.admin(), source_id=virtual.id, target_id=host.id, type_key="installed_in"
            ),
        )

    assert edge_count(catalog) == 3


def test_host_move_replaces_the_relationship_and_preserves_identity(catalog: Catalog) -> None:
    old_host = create_asset(catalog, quick_code="MOV-001")
    new_host = create_asset(catalog, quick_code="MOV-002")
    virtual = create_asset(
        catalog,
        quick_code="MOV-003",
        technical={"vcpu": 4, "hypervisor": "kvm"},
    )
    original = write(
        catalog,
        lambda service: service.create(
            catalog.admin(), source_id=virtual.id, target_id=old_host.id, type_key="hosted_in"
        ),
    )

    moved = write(
        catalog,
        lambda service: service.move_host(
            catalog.admin(),
            virtual.id,
            new_host.id,
            reason="migración planificada",
            notes="ventana nocturna",
            effective_at=EFFECTIVE,
        ),
    )

    assert moved.child_id == virtual.id
    assert moved.old_relationship is not None
    assert moved.old_relationship.id == original.id
    assert moved.old_relationship.target_id == old_host.id
    assert moved.new_relationship.source_id == virtual.id
    assert moved.new_relationship.target_id == new_host.id
    assert moved.new_relationship.type_key == "hosted_in"
    assert moved.new_relationship.id != original.id

    with catalog.session() as session:
        current = InventoryService(session, catalog.settings).get(catalog.admin(), virtual.id)
    assert current.id == virtual.id
    assert current.technical == {"vcpu": 4, "hypervisor": "kvm"}

    relations = read(
        catalog,
        lambda service: service.list(catalog.admin(), asset_id=virtual.id, type_key="hosted_in"),
    )
    assert [(item.target_id, item.id) for item in relations.items] == [
        (new_host.id, moved.new_relationship.id)
    ]

    child_history = history(catalog, virtual.id)
    move_entry = child_history[-1]
    assert move_entry.action == "host_moved"
    assert move_entry.changes["host"]["old"] == old_host.id
    assert move_entry.changes["host"]["new"] == new_host.id
    assert move_entry.reason == "migración planificada"
    assert move_entry.notes == "ventana nocturna"
    assert move_entry.effective_at == EFFECTIVE
    assert move_entry.entity_type == "relationship"
    assert move_entry.entity_id == moved.new_relationship.id

    old_host_entry = history(catalog, old_host.id)[-1]
    new_host_entry = history(catalog, new_host.id)[-1]
    assert old_host_entry.action == "host_moved"
    assert old_host_entry.changes["hostedChild"] == {"old": virtual.id, "new": None}
    assert new_host_entry.changes["hostedChild"] == {"old": None, "new": virtual.id}


def test_host_move_rejects_invalid_targets_without_writes(catalog: Catalog) -> None:
    host = create_asset(catalog, quick_code="BAD-001")
    archived_host = create_asset(catalog, quick_code="BAD-002")
    virtual = create_asset(catalog, quick_code="BAD-003")
    write(
        catalog,
        lambda service: service.create(
            catalog.admin(), source_id=virtual.id, target_id=host.id, type_key="hosted_in"
        ),
    )
    with catalog.session() as session:
        InventoryService(session, catalog.settings).archive(
            catalog.admin(), archived_host.id, reason="retirado"
        )
    edges_before = edge_count(catalog)
    history_before = history_count(catalog)
    sequence_before = max_sequence(catalog)

    with pytest.raises(Conflict):
        write(
            catalog,
            lambda service: service.move_host(
                catalog.admin(), virtual.id, archived_host.id, reason="destino retirado"
            ),
        )
    with pytest.raises(ValidationFailed):
        write(
            catalog,
            lambda service: service.move_host(
                catalog.admin(), virtual.id, virtual.id, reason="destino inválido"
            ),
        )
    with pytest.raises(Conflict):
        write(
            catalog,
            lambda service: service.move_host(
                catalog.admin(), archived_host.id, host.id, reason="sin alojamiento"
            ),
        )
    with pytest.raises(ValidationFailed):
        write(
            catalog,
            lambda service: service.move_host(catalog.admin(), virtual.id, host.id, reason=""),
        )

    assert edge_count(catalog) == edges_before
    assert history_count(catalog) == history_before
    assert max_sequence(catalog) == sequence_before


def test_relationship_update_records_old_and_new_values_on_both_endpoints(
    catalog: Catalog,
) -> None:
    source = create_asset(catalog, quick_code="UPD-001")
    target = create_asset(catalog, quick_code="UPD-002")
    edge = write(
        catalog,
        lambda service: service.create(
            catalog.admin(), source_id=source.id, target_id=target.id, type_key="connected_to"
        ),
    )

    updated = write(
        catalog,
        lambda service: service.update(
            catalog.admin(),
            edge.id,
            type_key="depends_on",
            reason="cambio de dependencia",
            notes="revisado",
            effective_at=EFFECTIVE,
        ),
    )

    assert updated.type_key == "depends_on"
    assert updated.forward_label == "Depende de"
    for asset_id in (source.id, target.id):
        entry = history(catalog, asset_id)[-1]
        assert entry.action == "relationship_updated"
        assert entry.changes["relationship"]["old"]["type"] == "connected_to"
        assert entry.changes["relationship"]["new"]["type"] == "depends_on"


def test_relationship_remove_records_history_on_both_endpoints(catalog: Catalog) -> None:
    source = create_asset(catalog, quick_code="REM-001")
    target = create_asset(catalog, quick_code="REM-002")
    edge = write(
        catalog,
        lambda service: service.create(
            catalog.admin(), source_id=source.id, target_id=target.id, type_key="associated_with"
        ),
    )

    removed = write(
        catalog,
        lambda service: service.remove(
            catalog.admin(), edge.id, reason="ya no aplica", notes="fin de servicio"
        ),
    )

    assert removed.id == edge.id
    assert edge_count(catalog) == 0
    for asset_id in (source.id, target.id):
        entry = history(catalog, asset_id)[-1]
        assert entry.action == "relationship_removed"
        assert entry.changes["relationship"]["old"]["id"] == edge.id
        assert entry.changes["relationship"]["new"] is None
        assert entry.notes == "fin de servicio"

    with pytest.raises(NotFound):
        write(catalog, lambda service: service.remove(catalog.admin(), edge.id))


def test_relationship_history_carries_trusted_source_entity_actor_and_effective_time(
    catalog: Catalog,
) -> None:
    source = create_asset(catalog, quick_code="HIS-001")
    target = create_asset(catalog, quick_code="HIS-002")

    session = catalog.factory()()
    try:
        service = RelationshipService(session, catalog.settings, source="agent")
        edge = service.create(
            catalog.admin(),
            source_id=source.id,
            target_id=target.id,
            type_key="depends_on",
            reason="dependencia crítica",
            notes="proveedor externo",
            effective_at=EFFECTIVE,
        )
    finally:
        session.close()

    entry = history(catalog, source.id)[-1]
    assert entry.source == "agent"
    assert entry.entity_type == "relationship"
    assert entry.entity_id == edge.id
    assert entry.actor_username == catalog.admin().username
    assert entry.effective_at == EFFECTIVE
    assert entry.created_at != entry.effective_at
    assert entry.effective_at.tzinfo is not None
    assert entry.notes == "proveedor externo"


def test_naive_effective_time_is_rejected_without_writes(catalog: Catalog) -> None:
    source = create_asset(catalog, quick_code="TZ-001")
    target = create_asset(catalog, quick_code="TZ-002")
    edges_before = edge_count(catalog)
    history_before = history_count(catalog)

    with pytest.raises(ValidationFailed):
        write(
            catalog,
            lambda service: service.create(
                catalog.admin(),
                source_id=source.id,
                target_id=target.id,
                type_key="connected_to",
                effective_at=datetime(2026, 5, 12, 14, 30),
            ),
        )

    assert edge_count(catalog) == edges_before
    assert history_count(catalog) == history_before


def test_relationship_mutations_require_assets_edit(catalog: Catalog) -> None:
    catalog.add_user(*READER)
    catalog.add_user(*OPERATOR)
    reader = catalog.principal(READER[0])
    operator = catalog.principal(OPERATOR[0])
    source = create_asset(catalog, quick_code="PERM-001")
    target = create_asset(catalog, quick_code="PERM-002")

    with pytest.raises(PermissionDenied):
        write(
            catalog,
            lambda service: service.create(
                reader, source_id=source.id, target_id=target.id, type_key="connected_to"
            ),
        )

    edge = write(
        catalog,
        lambda service: service.create(
            operator, source_id=source.id, target_id=target.id, type_key="connected_to"
        ),
    )
    assert edge.id


def test_bulk_relationship_query_is_bounded_to_fifty_assets(catalog: Catalog) -> None:
    first = create_asset(catalog, quick_code="BLK-001")
    second = create_asset(catalog, quick_code="BLK-002")
    write(
        catalog,
        lambda service: service.create(
            catalog.admin(), source_id=first.id, target_id=second.id, type_key="connected_to"
        ),
    )

    page = read(
        catalog,
        lambda service: service.list(catalog.admin(), asset_ids=[first.id, second.id]),
    )
    assert page.total == 1

    with pytest.raises(ValidationFailed):
        read(
            catalog,
            lambda service: service.list(catalog.admin(), asset_ids=[first.id] * 51),
        )


# --------------------------------------------------------------------- graph
def test_graph_traverses_bounded_depth_in_both_directions(catalog: Catalog) -> None:
    assets = [create_asset(catalog, quick_code=f"GRA-{index:03d}") for index in range(4)]
    for parent, child in itertools.pairwise(assets):
        write(
            catalog,
            lambda service, parent=parent, child=child: service.create(
                catalog.admin(), source_id=parent.id, target_id=child.id, type_key="connected_to"
            ),
        )

    one_level = read(
        catalog,
        lambda service: service.graph(catalog.admin(), root_id=assets[1].id, depth=1),
    )
    assert {node.id for node in one_level.nodes} == {assets[0].id, assets[1].id, assets[2].id}
    assert len(one_level.edges) == 2
    assert one_level.depth_truncated is True

    two_levels = read(
        catalog,
        lambda service: service.graph(catalog.admin(), root_id=assets[1].id, depth=2),
    )
    assert {node.id for node in two_levels.nodes} == {asset.id for asset in assets}

    outward = read(
        catalog,
        lambda service: service.graph(
            catalog.admin(), root_id=assets[0].id, depth=2, direction="out"
        ),
    )
    assert {node.id for node in outward.nodes} == {assets[0].id, assets[1].id, assets[2].id}

    inward = read(
        catalog,
        lambda service: service.graph(
            catalog.admin(), root_id=assets[2].id, depth=2, direction="in"
        ),
    )
    assert {node.id for node in inward.nodes} == {assets[0].id, assets[1].id, assets[2].id}
    assert all(edge.direction == "incoming" for edge in inward.edges)


def test_graph_bulk_seeds_are_bounded_and_validated(catalog: Catalog) -> None:
    first = create_asset(catalog, quick_code="GBK-001")
    second = create_asset(catalog, quick_code="GBK-002")
    write(
        catalog,
        lambda service: service.create(
            catalog.admin(), source_id=first.id, target_id=second.id, type_key="connected_to"
        ),
    )

    graph = read(
        catalog,
        lambda service: service.graph(catalog.admin(), asset_ids=[first.id], depth=1),
    )
    assert {node.id for node in graph.nodes} == {first.id, second.id}
    assert len(graph.edges) == 1

    with pytest.raises(ValidationFailed):
        read(
            catalog,
            lambda service: service.graph(catalog.admin(), asset_ids=[first.id] * 51),
        )
    with pytest.raises(NotFound):
        read(
            catalog,
            lambda service: service.graph(
                catalog.admin(), asset_ids=[first.id, "00000000-0000-0000-0000-000000000000"]
            ),
        )
    with pytest.raises(ValidationFailed):
        read(
            catalog,
            lambda service: service.graph(
                catalog.admin(), root_id=first.id, depth=MAX_GRAPH_DEPTH + 1
            ),
        )


def test_graph_truncates_nodes_and_edges_with_explicit_flags(
    catalog: Catalog, monkeypatch: pytest.MonkeyPatch
) -> None:
    center = create_asset(catalog, quick_code="TRN-000")
    leaves = [create_asset(catalog, quick_code=f"TRN-{index:03d}") for index in range(1, 5)]
    for leaf in leaves:
        write(
            catalog,
            lambda service, leaf=leaf: service.create(
                catalog.admin(), source_id=center.id, target_id=leaf.id, type_key="connected_to"
            ),
        )

    monkeypatch.setattr(relationship_module, "MAX_GRAPH_NODES", 2)
    monkeypatch.setattr(relationship_module, "MAX_GRAPH_EDGES", 2)
    graph = read(
        catalog,
        lambda service: service.graph(catalog.admin(), root_id=center.id, depth=1),
    )

    assert len(graph.nodes) == 2
    assert graph.nodes_truncated is True
    assert graph.edges_truncated is True
    assert graph.truncated is True


def test_graph_global_exploration_is_paginated_and_includes_archived_nodes(
    catalog: Catalog,
) -> None:
    first = create_asset(catalog, quick_code="GGL-001")
    second = create_asset(catalog, quick_code="GGL-002")
    third = create_asset(catalog, quick_code="GGL-003")
    for index, target in enumerate((second, third)):
        write(
            catalog,
            lambda service, index=index, target=target: service.create(
                catalog.admin(),
                source_id=first.id,
                target_id=target.id,
                type_key="connected_to" if index == 0 else "depends_on",
            ),
        )
    with catalog.session() as session:
        InventoryService(session, catalog.settings).archive(
            catalog.admin(), third.id, reason="retirado"
        )

    page = read(catalog, lambda service: service.graph(catalog.admin(), limit=2))

    assert page.total == 2
    assert len(page.edges) == 2
    assert {node.id for node in page.nodes} == {first.id, second.id, third.id}
    assert next(node for node in page.nodes if node.id == third.id).archived is True


def test_graph_requires_assets_view(catalog: Catalog) -> None:
    catalog.add_user(*READER)
    reader = catalog.principal(READER[0])
    asset = create_asset(catalog, quick_code="GPR-001")

    graph = read(catalog, lambda service: service.graph(reader, root_id=asset.id))
    assert [node.id for node in graph.nodes] == [asset.id]


# ------------------------------------------------------- structured history
def test_default_asset_history_is_trusted_internal_for_the_asset_entity(
    catalog: Catalog,
) -> None:
    with catalog.session() as session:
        service = InventoryService(session, catalog.settings)
        created = service.create(catalog.admin(), asset_values(quick_code="STR-001"))
        entry = service.history(catalog.admin(), created.id).items[0]

    assert entry.source == "internal"
    assert entry.entity_type == "asset"
    assert entry.entity_id == created.id
    assert entry.effective_at is None
    assert entry.notes is None
    assert entry.actor_username == catalog.admin().username
    legacy_payload = entry.as_payload()
    assert legacy_payload["assetId"] == created.id
    assert legacy_payload["action"] == "created"
    structured = entry.structured_payload()
    assert structured["source"] == "internal"
    assert structured["entityType"] == "asset"
    assert structured["entityId"] == created.id
    assert "createdAt" in structured


def test_lifecycle_events_use_the_constructor_source(catalog: Catalog) -> None:
    with catalog.session() as session:
        service = InventoryService(session, catalog.settings, source="rest")
        created = service.create(catalog.admin(), asset_values(quick_code="SRC-100"))
        service.archive(catalog.admin(), created.id, reason="guardado")
        service.restore(catalog.admin(), created.id)
        entries = service.history(catalog.admin(), created.id).items

    assert [entry.action for entry in entries] == ["created", "archived", "restored"]
    assert all(entry.source == "rest" for entry in entries)
    assert all(entry.entity_type == "asset" for entry in entries)
    assert all(entry.entity_id == created.id for entry in entries)


def test_service_source_keyword_only_accepts_trusted_values(catalog: Catalog) -> None:
    with catalog.session() as session:
        with pytest.raises(ValidationFailed):
            InventoryService(session, catalog.settings, source="request")
        with pytest.raises(ValidationFailed):
            RelationshipService(session, catalog.settings, source="request")


def test_structured_payload_preserves_every_legacy_field(catalog: Catalog) -> None:
    with catalog.session() as session:
        service = InventoryService(session, catalog.settings)
        created = service.create(catalog.admin(), asset_values(quick_code="LEG-001"))
        entry = service.history(catalog.admin(), created.id).items[0]

    legacy = set(entry.as_payload())
    structured = set(entry.structured_payload())
    assert legacy <= structured
    assert structured - legacy == {"source", "entityType", "entityId", "effectiveAt", "notes"}
