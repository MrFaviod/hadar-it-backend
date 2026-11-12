"""Public inventory projections: every advertised field must be projectable."""

from __future__ import annotations

from datetime import UTC, datetime
from decimal import Decimal

import pytest
from itsm.identity.service import ValidationFailed
from itsm.inventory.projection import PUBLIC_FIELDS, project, validate_fields
from itsm.inventory.service import AssetView


def _view() -> AssetView:
    now = datetime(2026, 1, 1, tzinfo=UTC)
    return AssetView(
        id="a1",
        quick_code="QC1",
        name="Laptop",
        category=None,
        type=None,
        brand=None,
        model=None,
        serial=None,
        ip=None,
        site=None,
        location=None,
        responsible=None,
        site_id=None,
        location_id=None,
        responsible_person_id=None,
        responsible_label=None,
        position_x=None,
        position_y=None,
        status="in_use",
        status_label="En uso",
        description=None,
        cost=Decimal("1.00"),
        technical=None,
        archived=False,
        archived_at=None,
        archived_by=None,
        images={},
        created_at=now,
        updated_at=now,
    )


def test_every_public_field_can_be_projected():
    payload = _view().as_payload()
    for name in PUBLIC_FIELDS:
        assert name in payload, f"public field {name!r} is not emitted by as_payload"
        assert project(_view(), [name]) == {name: payload[name]}


def test_status_label_snake_case_is_refused_not_a_key_error():
    with pytest.raises(ValidationFailed):
        validate_fields(["status_label"])
