"""Read-only resolution of permanent core ids for an extension.

An extension stores core identifiers, never core rows. This helper answers the
only question it needs after a change or during reconciliation: is this id still
usable? It reuses the canonical services, so Casbin keeps its single authority
over who may read inventory or maintenance — no extension-specific bypass and no
direct SQL against core tables.
"""

from __future__ import annotations

from collections.abc import Sequence
from typing import Final

from sqlalchemy.orm import Session

from itsm.config import Settings
from itsm.identity.service import Principal, ValidationFailed
from itsm.interventions.service import InterventionService
from itsm.inventory.service import InventoryService

MAX_REFERENCE_IDS: Final[int] = 200
REFERENCE_ENTITY_TYPES: Final[tuple[str, ...]] = ("asset", "incident")
REFERENCE_STATES: Final[tuple[str, ...]] = ("active", "archived", "missing")


def _entity_type(value: object) -> str:
    if not isinstance(value, str) or value not in REFERENCE_ENTITY_TYPES:
        raise ValidationFailed("entity_type must be asset or incident")
    return value


def _identifiers(values: object) -> list[str]:
    if isinstance(values, (str, bytes)) or not isinstance(values, Sequence):
        raise ValidationFailed("ids must be a list of permanent identifiers")
    if len(values) > MAX_REFERENCE_IDS:
        raise ValidationFailed(f"at most {MAX_REFERENCE_IDS} ids may be resolved at once")
    ordered: list[str] = []
    for value in values:
        if not isinstance(value, str):
            raise ValidationFailed("ids must contain strings")
        identifier = value.strip()
        if not identifier or len(identifier) > 36:
            raise ValidationFailed("ids must be 1-36 characters")
        if identifier not in ordered:
            ordered.append(identifier)
    return ordered


def resolve_entities(
    principal: Principal,
    entity_type: str,
    ids: Sequence[str],
    *,
    session: Session,
    settings: Settings,
) -> dict[str, str]:
    """Map each permanent id to ``active``, ``archived`` or ``missing``.

    Incidents have no archive flag in the core lifecycle, so their result is
    ``active`` or ``missing`` only. The caller's own permission is enforced by
    the referenced service, exactly as a REST or agent read would be.
    """
    kind = _entity_type(entity_type)
    identifiers = _identifiers(ids)
    if not identifiers:
        return {}
    if kind == "asset":
        return InventoryService(session, settings).reference_states(principal, identifiers)
    return InterventionService(session, settings).incident_reference_states(principal, identifiers)


__all__ = [
    "MAX_REFERENCE_IDS",
    "REFERENCE_ENTITY_TYPES",
    "REFERENCE_STATES",
    "resolve_entities",
]
