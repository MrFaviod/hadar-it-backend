"""Serialized, transaction-bound inventory code allocation on supported SQL engines."""

from __future__ import annotations

import re
import unicodedata
from functools import wraps
from typing import Any

from sqlalchemy import Integer, String, select, update
from sqlalchemy.orm import Mapped, mapped_column

from itsm.identity.service import Conflict, ValidationFailed
from itsm.inventory.models import Asset, InventoryBase


class InventoryCodeSequence(InventoryBase):
    __tablename__ = "inventory_code_sequences"
    key: Mapped[str] = mapped_column(String(64), primary_key=True)
    next_value: Mapped[int] = mapped_column(Integer, nullable=False)


def serialized(method):
    """Take the database write mutex before reading state; rollback failed writes.

    UPDATE locks the single existing row on PostgreSQL/MariaDB and obtains the
    SQLite writer reservation. The lock and every sequence change belong to the
    same transaction as the asset, history and business audit. No process lock,
    optimistic max+1 race, side connection or independent sequence commit.
    """

    @wraps(method)
    def wrapped(self, *args, **kwargs):
        nested = getattr(self, "_inventory_write_depth", 0)
        self._inventory_write_depth = nested + 1
        try:
            if not nested:
                self._reserved_codes = set()
                self._pending_sequences = {}
                result = self._session.execute(
                    update(InventoryCodeSequence)
                    .where(InventoryCodeSequence.key == "__lock__")
                    .values(next_value=InventoryCodeSequence.next_value)
                )
                if result.rowcount != 1:
                    raise Conflict("inventory schema is not ready; run migrations")
            return method(self, *args, **kwargs)
        except Exception:
            self._session.rollback()
            raise
        finally:
            self._inventory_write_depth = nested

    return wrapped


def abbreviation(value: str, length: int) -> str:
    normalized = unicodedata.normalize("NFKD", value)
    return "".join(c for c in normalized.upper() if c.isascii() and c.isalnum())[:length] or "NA"


def allocate(
    service: Any,
    values: dict[str, Any],
    *,
    requested: str | None = None,
    exclude_id: str | None = None,
) -> str | None:
    """Allocate a configured code, or retain legacy random/manual behavior."""
    catalog = service._catalog
    if requested:
        match = re.fullmatch(r"(.*?)(\d+)", requested)
        if not match:
            service._assert_quick_code_free(requested, exclude_id=exclude_id)
            return requested
        prefix, digits = match.groups()
        start, pad = int(digits), len(digits)
    else:
        form = catalog.category(values.get("category"))
        if form is None:
            return None
        rules = catalog._entry("rules", "identification").payload
        site = values.get("site") or values.get("location") or "NA"
        site_code = rules["siteCodes"].get(site, abbreviation(site, rules["siteCodeLength"]))
        kind = form["prefix"]
        parts = [site_code, kind] if rules["order"] == "site-type" else [kind, site_code]
        if not rules["includeSite"]:
            parts = [kind]
        prefix = rules["separator"].join(parts) + rules["separator"]
        start, pad = 1, rules["quickPad"]
    if len(prefix) + pad > 32 or start > 2_000_000_000:
        raise ValidationFailed("quickCode sequence exceeds the supported format")
    key = prefix.lower()
    sequence = service._session.get(InventoryCodeSequence, key)
    pending = service._pending_sequences.get(key, sequence.next_value if sequence else start)
    candidate = start if requested else max(start, pending)
    for _ in range(10000):
        code = prefix + str(candidate).zfill(pad)
        if len(code) > 32 or candidate > 2_000_000_000:
            raise Conflict("quickCode sequence is exhausted")
        query = select(Asset.id).where(Asset.quick_code_key == code.lower())
        if exclude_id:
            query = query.where(Asset.id != exclude_id)
        reserved = getattr(service, "_reserved_codes", set())
        if code.lower() not in reserved and service._session.execute(query).first() is None:
            service._pending_sequences[key] = max(pending, candidate + 1)
            reserved.add(code.lower())
            service._reserved_codes = reserved
            return code
        candidate += 1
    raise Conflict("could not find an available quickCode within the allocation bound")
