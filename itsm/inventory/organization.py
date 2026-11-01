"""Canonical asset organization: directory references, labels and plan positions.

The reference identifiers are the authority. When an asset carries ``site_id``,
``location_id`` or ``responsible_person_id``, the legacy ``site``, ``location``
and ``responsible`` text is only a mirror of the current canonical label:

* an id alone fills its mirrored text from the directory;
* the legacy text alone, including an explicit ``null``, clears the stale
  reference of the same dimension;
* both together are accepted only when the text already equals the canonical
  label, otherwise the request is contradictory and rejected.

A cleared or switched site also drops the stored location and plan position of
the previous site, unless the same request names a valid replacement location.
Clearing the location alone keeps the site. That single rule keeps old callers
working, never leaves a mismatched pair and never duplicates the label as a
second authority: labels are derived on read by ``InventoryService`` from the
referenced directory row.

This module owns the bounded validation and resolution helpers used by
``InventoryService``. It never authorizes, never mutates and never commits:
authorization stays in the inventory service and the referential rules stay in
``DirectoryService``.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from datetime import datetime
from decimal import Decimal, InvalidOperation
from typing import Any
from uuid import UUID

from sqlalchemy import select

from itsm.identity.service import Conflict, Principal, ValidationFailed

POSITION_DECIMALS = 6
MAX_LOCATION_DESCENDANTS = 200
ORGANIZATION_FIELDS: tuple[str, ...] = (
    "site_id",
    "location_id",
    "responsible_person_id",
    "position_x",
    "position_y",
)
REFERENCE_FIELDS: tuple[str, ...] = ("site_id", "location_id", "responsible_person_id")
LEGACY_FIELDS: tuple[str, ...] = ("site", "location", "responsible")
RESOLVED_FIELDS: tuple[str, ...] = (*ORGANIZATION_FIELDS, *LEGACY_FIELDS)
POSITION_FIELDS: tuple[str, ...] = ("position_x", "position_y")
# Which canonical reference each legacy text mirrors; a clone re-derives the text
# from the id instead of copying a snapshot that a directory rename made stale.
MIRROR_IDS: dict[str, str] = {
    "site": "site_id",
    "location": "location_id",
    "responsible": "responsible_person_id",
}

_LOCATION_LEVELS = frozenset({"building", "floor", "room_zone"})
_MAX_HOPS = 4


# ---------------------------------------------------------------- validation
def reference(value: Any, field: str) -> str | None:
    """Accept ``None`` or a UUID; the directory decides if it exists and is active."""
    if value is None:
        return None
    if not isinstance(value, str) or not value.strip():
        raise ValidationFailed(
            f"{field} must be a UUID",
            key="api.validation.field_uuid",
            params={"field": field},
        )
    checked = value.strip()
    try:
        UUID(checked)
    except ValueError:
        raise ValidationFailed(
            f"{field} must be a UUID",
            key="api.validation.field_uuid",
            params={"field": field},
        ) from None
    return checked


def position(value: Any, field: str) -> str | None:
    """Canonical decimal string inside the relative ``0..1`` plan band."""
    if value is None:
        return None
    if isinstance(value, bool) or not isinstance(value, str | int | float | Decimal):
        raise ValidationFailed(
            f"{field} must be a number",
            key="api.validation.field_number",
            params={"field": field},
        )
    try:
        parsed = Decimal(str(value).strip())
    except InvalidOperation:
        raise ValidationFailed(
            f"{field} must be a number",
            key="api.validation.field_number",
            params={"field": field},
        ) from None
    if not parsed.is_finite():
        raise ValidationFailed(
            f"{field} must be a finite number",
            key="api.inventory.position_finite",
            params={"field": field},
        )
    if parsed < 0 or parsed > 1:
        raise ValidationFailed(
            f"{field} must be between 0 and 1",
            key="api.inventory.position_range",
            params={"field": field},
        )
    if -parsed.as_tuple().exponent > POSITION_DECIMALS:
        raise ValidationFailed(
            f"{field} accepts at most {POSITION_DECIMALS} decimals",
            key="api.inventory.position_decimals",
            params={"field": field, "limit": POSITION_DECIMALS},
        )
    return format(parsed.normalize(), "f")


def moment(value: str | None) -> datetime | None:
    """Parse an adapter-supplied ISO 8601 instant; the service validates the zone."""
    if value is None:
        return None
    try:
        parsed = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except ValueError:
        raise ValidationFailed(
            "effectiveAt must be an ISO 8601 timestamp",
            key="api.inventory.effective_at_iso8601",
        ) from None
    if parsed.tzinfo is None:
        raise ValidationFailed(
            "effectiveAt must include a timezone offset",
            key="api.inventory.effective_at_timezone",
        )
    return parsed


def number(value: str | None) -> float | None:
    """Expose a stored canonical position as a number, never as a stored float."""
    return None if value is None else float(value)


def check_position(values: Mapping[str, Any], *, location_id: str | None) -> None:
    """A position is an optional consistent pair and needs a location plan."""
    x = values.get("position_x")
    y = values.get("position_y")
    if x is None and y is None:
        return
    if (x is None) != (y is None):
        raise ValidationFailed(
            "positionX and positionY must be provided together",
            key="api.inventory.position_pair",
        )
    if location_id is None:
        raise ValidationFailed(
            "a plan position requires a locationId", key="api.inventory.position_location"
        )


# ------------------------------------------------------------ directory reads
def _active(directory: Any, principal: Principal, location_id: str) -> Any:
    view = directory.get_location(principal, location_id)
    if not view.active:
        raise ValidationFailed(
            "the referenced location is inactive", key="api.inventory.location_inactive"
        )
    return view


def _site(directory: Any, principal: Principal, site_id: str) -> Any:
    view = _active(directory, principal, site_id)
    if view.level != "site":
        raise ValidationFailed("siteId must reference a site", key="api.inventory.site_reference")
    return view


def _site_ancestor(directory: Any, principal: Principal, location: Any) -> Any:
    current = location
    for _ in range(_MAX_HOPS + 1):
        if current.level == "site":
            return current
        if current.parent_id is None:
            raise ValidationFailed(
                "locationId is not inside a site", key="api.inventory.location_outside_site"
            )
        current = _active(directory, principal, current.parent_id)
    raise ValidationFailed(
        "locationId hierarchy is deeper than the supported depth",
        key="api.inventory.location_depth",
    )


def descendant_ids(session: Any, location_id: str) -> list[str]:
    """Bounded subtree ids for a hierarchical filter; too large a subtree is an error."""
    from itsm.directory.models import DirectoryLocation

    found = [location_id]
    frontier = [location_id]
    while frontier:
        rows = (
            session.execute(
                select(DirectoryLocation.id).where(DirectoryLocation.parent_id.in_(frontier))
            )
            .scalars()
            .all()
        )
        children = [row for row in rows if row not in found]
        if not children:
            return found
        found.extend(children)
        if len(found) > MAX_LOCATION_DESCENDANTS:
            raise ValidationFailed(
                f"locationId matches more than {MAX_LOCATION_DESCENDANTS} locations; "
                "narrow the filter",
                key="api.inventory.location_descendants_limit",
                params={"limit": MAX_LOCATION_DESCENDANTS},
            )
        frontier = children
    return found


# ---------------------------------------------------------------- resolution
def resolve(
    values: Mapping[str, Any],
    *,
    stored: Mapping[str, Any],
    directory: Any,
    principal: Principal,
) -> dict[str, Any]:
    """Resolve the touched reference/text pairs into the keys the service applies."""
    touched = set(values)
    resolved: dict[str, Any] = {}
    resolved.update(_resolve_person(values, touched, directory=directory, principal=principal))
    resolved.update(
        _resolve_place(values, touched, stored=stored, directory=directory, principal=principal)
    )
    return resolved


def _resolve_person(
    values: Mapping[str, Any],
    touched: set[str],
    *,
    directory: Any,
    principal: Principal,
) -> dict[str, Any]:
    """One nullable pair: the id derives the label, otherwise the text wins alone."""
    person_touched = "responsible_person_id" in touched
    text_touched = "responsible" in touched
    if not person_touched and not text_touched:
        return {}
    person_id = (
        reference(values["responsible_person_id"], "responsiblePersonId")
        if person_touched
        else None
    )
    text = values.get("responsible") if text_touched else None
    if person_id is not None:
        try:
            label = directory.person_label(principal, person_id, require_active=True)
        except Conflict as error:
            raise ValidationFailed(
                str(error), key="api.inventory.responsible_not_available"
            ) from None
        if text is not None and text != label:
            raise ValidationFailed(
                "responsible and responsiblePersonId must agree",
                key="api.inventory.responsible_text_mismatch",
            )
        return {"responsible_person_id": person_id, "responsible": label}
    # A cleared or text-only switch drops the stale reference and mirrors the text,
    # so an explicit ``None`` never leaves half of the pair behind.
    return {"responsible_person_id": None, "responsible": text}


def _resolve_place(
    values: Mapping[str, Any],
    touched: set[str],
    *,
    stored: Mapping[str, Any],
    directory: Any,
    principal: Principal,
) -> dict[str, Any]:
    """Resolve site/location and drop a location that its site no longer covers."""
    site_touched = "site_id" in touched
    site_text_touched = "site" in touched
    location_touched = "location_id" in touched
    location_text_touched = "location" in touched
    if not (site_touched or site_text_touched or location_touched or location_text_touched):
        return {}

    site_id = reference(values["site_id"], "siteId") if site_touched else None
    location_id = reference(values["location_id"], "locationId") if location_touched else None
    site_text = values.get("site") if site_text_touched else None
    location_text = values.get("location") if location_text_touched else None
    site = _site(directory, principal, site_id) if site_id is not None else None
    if site is not None and site_text is not None and site_text != site.name:
        raise ValidationFailed("site and siteId must agree", key="api.inventory.site_text_mismatch")

    if location_id is not None:
        location = _active(directory, principal, location_id)
        if location.level not in _LOCATION_LEVELS:
            raise ValidationFailed(
                "locationId must reference a building, floor or room/zone",
                key="api.inventory.location_level_allowed",
            )
        if location_text is not None and location_text != location.name:
            raise ValidationFailed(
                "location and locationId must agree",
                key="api.inventory.location_text_mismatch",
            )
        ancestor = _site_ancestor(directory, principal, location)
        if site is not None and ancestor.id != site.id:
            raise ValidationFailed(
                "locationId must belong to the selected site",
                key="api.inventory.location_site_mismatch",
            )
        if site_text is not None and site_text != ancestor.name:
            raise ValidationFailed(
                "site and siteId must agree", key="api.inventory.site_text_mismatch"
            )
        # An explicit valid location is the replacement: nothing else becomes stale.
        return {
            "site_id": ancestor.id,
            "site": ancestor.name,
            "location_id": location.id,
            "location": location.name,
        }

    resolved: dict[str, Any] = {}
    if location_touched or location_text_touched:
        # An explicit ``None`` id clears the mirror unless the same request also
        # names the replacement legacy text; legacy text alone drops the reference.
        resolved["location_id"] = None
        resolved["location"] = location_text

    if site is not None:
        resolved["site_id"] = site.id
        resolved["site"] = site.name
    elif site_touched or site_text_touched:
        resolved["site_id"] = None
        resolved["site"] = site_text

    if not location_touched and not location_text_touched and (site_touched or site_text_touched):
        dropped = site is None or site.id != stored.get("site_id")
        if dropped and (stored.get("location_id") or stored.get("location")):
            resolved["location_id"] = None
            resolved["location"] = None
    return resolved


def validate_stored(stored: Mapping[str, Any], *, directory: Any, principal: Principal) -> None:
    """Revalidate the effective references of a stored asset before a restore.

    Directory deactivation deliberately ignores archived assets, so returning one
    to the active inventory is the moment to prove its references are usable
    again. Only canonical ids are checked: legacy-only assets keep working.
    """
    site_id = stored.get("site_id")
    location_id = stored.get("location_id")
    if site_id is not None:
        _site(directory, principal, site_id)
    if location_id is not None:
        location = _active(directory, principal, location_id)
        if location.level not in _LOCATION_LEVELS:
            raise ValidationFailed(
                "locationId must reference a building, floor or room/zone",
                key="api.inventory.location_level_allowed",
            )
        ancestor = _site_ancestor(directory, principal, location)
        if site_id is not None and ancestor.id != site_id:
            raise ValidationFailed(
                "locationId must belong to the selected site",
                key="api.inventory.location_site_mismatch",
            )
    person_id = stored.get("responsible_person_id")
    if person_id is not None:
        try:
            directory.person_label(principal, person_id, require_active=True)
        except Conflict as error:
            raise ValidationFailed(
                str(error), key="api.inventory.responsible_not_available"
            ) from None


@dataclass(frozen=True)
class MapSite:
    """One site of the organizational map with its optional coordinates."""

    id: str
    name: str
    latitude: float | None
    longitude: float | None

    def as_payload(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "name": self.name,
            "latitude": self.latitude,
            "longitude": self.longitude,
        }


@dataclass(frozen=True)
class MapPosition:
    """One asset placed on a location plan by a bounded relative position."""

    asset_id: str
    quick_code: str
    name: str
    site_id: str
    location_id: str
    x: float | None
    y: float | None

    def as_payload(self) -> dict[str, Any]:
        return {
            "assetId": self.asset_id,
            "quickCode": self.quick_code,
            "name": self.name,
            "siteId": self.site_id,
            "locationId": self.location_id,
            "x": self.x,
            "y": self.y,
        }


@dataclass(frozen=True)
class AssetMap:
    """Bounded organizational map: sites and the assets that declare a position."""

    sites: tuple[MapSite, ...]
    positions: tuple[MapPosition, ...]
    limit: int
    offset: int
    truncated: bool

    def as_payload(self) -> dict[str, Any]:
        return {
            "sites": [site.as_payload() for site in self.sites],
            "positions": [item.as_payload() for item in self.positions],
            "limit": self.limit,
            "offset": self.offset,
            "truncated": self.truncated,
        }
