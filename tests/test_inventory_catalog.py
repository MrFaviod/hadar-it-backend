"""Catalog validation shared by inventory writers, independent of REST."""

from __future__ import annotations

import pytest
from itsm.identity.service import ValidationFailed
from tests.inventory_support import prepare


@pytest.mark.parametrize(
    "field,value,expected",
    [
        ({"key": "x", "label": "X", "type": "text"}, " abc ", "abc"),
        ({"key": "x", "label": "X", "type": "textarea"}, "notes", "notes"),
        ({"key": "x", "label": "X", "type": "number"}, 4.5, 4.5),
        ({"key": "x", "label": "X", "type": "date"}, "2026-10-21", "2026-10-21"),
        ({"key": "x", "label": "X", "type": "boolean"}, False, False),
        ({"key": "x", "label": "X", "type": "select", "options": ["A", "B"]}, "B", "B"),
        (
            {"key": "x", "label": "X", "type": "url"},
            "https://example.org/a",
            "https://example.org/a",
        ),
    ],
)
def test_reusable_typed_fields_validate_values(settings_factory, field, value, expected):
    # Import inside the test: a missing implementation must fail this behavior, not collection.
    from itsm.inventory.catalog import InventoryCatalog

    db = prepare(settings_factory)
    with db.session() as session:
        catalog = InventoryCatalog(session, db.settings)
        catalog.put(db.admin(), "fields", "x", field)
        metadata = catalog.get(db.admin())
        category = next(c for c in metadata["categories"] if c["id"] == "otros")
        catalog.put(db.admin(), "categories", "otros", {**category, "tech": ["x"]})
        assert catalog.validate_technical("otros", {"x": value}) == {"x": expected}
    db.engine.dispose()


@pytest.mark.parametrize(
    "kind,value",
    [
        ("number", True),
        ("number", float("inf")),
        ("date", "2026-02-30"),
        ("boolean", "false"),
        ("url", "javascript:alert(1)"),
        ("select", "Z"),
        ("text", 7),
    ],
)
def test_typed_fields_reject_invalid_input_without_modifying_catalog(settings_factory, kind, value):
    from itsm.inventory.catalog import InventoryCatalog

    db = prepare(settings_factory)
    with db.session() as session:
        catalog = InventoryCatalog(session, db.settings)
        field = {"key": "x", "label": "X", "type": kind}
        if kind == "select":
            field["options"] = ["A"]
        catalog.put(db.admin(), "fields", "x", field)
        category = next(c for c in catalog.get(db.admin())["categories"] if c["id"] == "otros")
        catalog.put(db.admin(), "categories", "otros", {**category, "tech": ["x"]})
        before = catalog.get(db.admin())
        with pytest.raises(ValidationFailed):
            catalog.validate_technical("otros", {"x": value})
        assert catalog.get(db.admin()) == before
    db.engine.dispose()


def test_defaults_optional_values_and_existing_values_survive_deactivation(settings_factory):
    from itsm.inventory.catalog import InventoryCatalog

    db = prepare(settings_factory)
    with db.session() as session:
        catalog = InventoryCatalog(session, db.settings)
        field = {"key": "x", "label": "X", "type": "number", "default": 16, "minimum": 0}
        catalog.put(db.admin(), "fields", "x", field)
        category = next(c for c in catalog.get(db.admin())["categories"] if c["id"] == "otros")
        catalog.put(db.admin(), "categories", "otros", {**category, "tech": ["x"]})
        assert catalog.validate_technical("otros", {}) == {"x": 16}
        catalog.put(db.admin(), "fields", "x", {**field, "active": False})
        assert catalog.validate_technical("otros", {"x": 8}, previous={"x": 8}) == {"x": 8}
        with pytest.raises(ValidationFailed):
            catalog.validate_technical("otros", {"x": 9}, previous={"x": 8})
    db.engine.dispose()


def test_transitions_category_override_and_state_independence(settings_factory):
    from itsm.inventory.catalog import InventoryCatalog

    db = prepare(settings_factory)
    with db.session() as session:
        catalog = InventoryCatalog(session, db.settings)
        catalog.put(
            db.admin(),
            "rules",
            "transitions",
            {"transitions": {"in_use": ["maintenance"], "maintenance": ["in_use"]}},
        )
        catalog.validate_transition("otros", "in_use", "maintenance")
        with pytest.raises(ValidationFailed):
            catalog.validate_transition("otros", "in_use", "retired")
        category = next(c for c in catalog.get(db.admin())["categories"] if c["id"] == "otros")
        catalog.put(
            db.admin(), "categories", "otros", {**category, "transitions": {"in_use": ["retired"]}}
        )
        catalog.validate_transition("otros", "in_use", "retired")
        with pytest.raises(ValidationFailed):
            catalog.validate_transition("otros", "in_use", "maintenance")
    db.engine.dispose()
