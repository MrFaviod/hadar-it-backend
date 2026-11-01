"""Persistent inventory metadata and reusable validation, shared by all adapters."""

from __future__ import annotations

import math
import re
from collections.abc import Mapping
from copy import deepcopy
from datetime import date
from typing import Any
from urllib.parse import urlsplit

from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from itsm.config import Settings
from itsm.i18n.labels import LabelError, label_view, validate_label
from itsm.identity.service import Conflict, IdentityService, NotFound, Principal, ValidationFailed
from itsm.inventory.catalog_defaults import COMMON_KEYS, FIELD_TYPES
from itsm.inventory.catalog_models import InventoryCatalogEntry

_KEY = re.compile(r"^[A-Za-z][A-Za-z0-9_.-]{0,63}$")
_KINDS = frozenset({"fields", "categories", "statuses", "rules"})
_MISSING = object()


def text(value: Any, label: str, limit: int = 120) -> str:
    if not isinstance(value, str) or not value.strip() or len(value.strip()) > limit:
        raise ValidationFailed(f"{label} must be non-empty text of at most {limit} characters")
    return value.strip()


def boolean(value: Any, label: str) -> bool:
    if not isinstance(value, bool):
        raise ValidationFailed(f"{label} must be a boolean")
    return value


def keys(value: Any, label: str, *, limit: int = 40) -> list[str]:
    if not isinstance(value, list) or len(value) > limit:
        raise ValidationFailed(f"{label} must be a list of at most {limit} entries")
    checked = [text(item, label, 64) for item in value]
    if len(set(checked)) != len(checked):
        raise ValidationFailed(f"{label} contains duplicate entries")
    return checked


def number(value: Any, label: str) -> float | int:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise ValidationFailed(f"{label} must be a finite number")
    if not math.isfinite(value) or abs(value) > 10**12:
        raise ValidationFailed(f"{label} is outside the supported numeric range")
    return value


def field_value(field: Mapping[str, Any], value: Any) -> Any:
    """Validate one value without fetching anything or coercing booleans/numbers."""
    if value is None:
        if field.get("required", False):
            raise ValidationFailed(f"{field['key']} is required")
        return None
    kind = field["type"]
    if kind == "number":
        result = number(value, field["key"])
        if field.get("minimum") is not None and result < field["minimum"]:
            raise ValidationFailed(f"{field['key']} is below its minimum")
        if field.get("maximum") is not None and result > field["maximum"]:
            raise ValidationFailed(f"{field['key']} exceeds its maximum")
        return result
    if kind == "boolean":
        return boolean(value, field["key"])
    result = text(value, field["key"], field.get("maxLength", 500))
    if kind == "date":
        try:
            parsed = date.fromisoformat(result)
        except ValueError:
            raise ValidationFailed(f"{field['key']} must be an ISO date") from None
        if parsed.isoformat() != result:
            raise ValidationFailed(f"{field['key']} must be an ISO date")
    elif kind == "url":
        try:
            url = urlsplit(result)
            valid = (
                url.scheme in {"http", "https"}
                and bool(url.hostname)
                and not url.username
                and not url.password
            )
        except ValueError:
            valid = False
        if not valid:
            raise ValidationFailed(f"{field['key']} must be an HTTP(S) URL without credentials")
    elif kind == "select" and result not in field["options"]:
        raise ValidationFailed(f"{field['key']} is not a configured option")
    return result


class InventoryCatalog:
    """Business-layer authorization and non-destructive metadata configuration."""

    def __init__(
        self,
        session: Session,
        settings: Settings,
        *,
        identity: IdentityService | None = None,
        locale: str | None = None,
    ):
        self.session = session
        self.settings = settings
        self.identity = identity or IdentityService(session, settings)
        self._locale = locale

    @property
    def label_locale(self) -> str:
        """Request locale the stored locale maps are rendered for.

        A caller without a request locale (agent, worker, CLI) gets the
        installation default instead of a hard-coded tag.
        """
        if self._locale is None:
            from itsm.i18n.settings import read_installation_settings

            self._locale = read_installation_settings(self.session).default_locale
        return self._locale

    def _label_pair(
        self, payload: Mapping[str, Any], *, field: str = "label", limit: int = 120
    ) -> tuple[str, dict[str, str] | None]:
        try:
            return validate_label(
                payload.get("label"), payload.get("labels"), field=field, limit=limit
            )
        except LabelError as exc:
            raise ValidationFailed(str(exc)) from None

    def _rendered(self, payload: Mapping[str, Any]) -> dict[str, Any]:
        """Stored row -> public view: resolved text plus the full label map."""
        item = deepcopy(dict(payload))
        if "label" in item:
            item.update(label_view(item["label"], item.get("labels"), self.label_locale))
        return item

    def _entry(self, kind: str, key: str) -> InventoryCatalogEntry | None:
        return self.session.get(InventoryCatalogEntry, (kind, key))

    def _items(self, kind: str) -> list[dict[str, Any]]:
        return [
            deepcopy(entry.payload)
            for entry in self.session.scalars(
                select(InventoryCatalogEntry)
                .where(InventoryCatalogEntry.kind == kind)
                .order_by(InventoryCatalogEntry.key)
            )
        ]

    def get(self, principal: Principal) -> dict[str, Any]:
        self.identity.authorize(principal, "assets.view", resource="inventory:config")
        result = {
            kind: [self._rendered(item) for item in self._items(kind)]
            for kind in ("fields", "categories", "statuses")
        }
        result["rules"] = {item["id"]: item for item in self._items("rules")}
        result["commonFields"] = list(COMMON_KEYS)
        production = self.settings.environment == "production"
        result["operations"] = {
            "environment": self.settings.environment,
            "purge": {
                "confirmationRequired": True,
                "humanOnly": True,
                "permission": "assets.purge" if production else "assets.edit",
                "archivedRequired": production,
                "typedIdRequired": production,
                "reasonRequired": production,
            },
        }
        return result

    def category(self, value: str | None) -> dict[str, Any] | None:
        """Resolve stable keys or any locale's label text; ids always win."""
        if not value:
            return None
        key = value.casefold()
        for item in self._items("categories"):
            if item["id"].casefold() == key:
                return item
            texts = {item["label"], *item.get("labels", {}).values()}
            if any(str(text).casefold() == key for text in texts):
                return item
        return None

    def validate_status(self, value: str) -> str:
        entry = self._entry("statuses", value)
        if entry is None or not entry.payload["active"]:
            raise ValidationFailed("status is not active in the inventory catalog")
        return value

    def validate_transition(self, category: str | None, old: str, new: str) -> None:
        if old == new:
            return
        self.validate_status(new)
        form = self.category(category)
        local = form.get("transitions") if form else None
        global_rule = self._entry("rules", "transitions")
        rules = (
            local
            if local is not None
            else global_rule.payload["transitions"]
            if global_rule
            else None
        )
        if rules is not None and new not in rules.get(old, []):
            raise ValidationFailed(f"status transition {old} -> {new} is not allowed")

    def validate_technical(
        self,
        category: str | None,
        values: Any,
        *,
        previous: Mapping[str, Any] | None = None,
        defaults: bool = True,
    ) -> dict[str, Any]:
        """Retain old disabled/unassociated fields unchanged; never erase stored values."""
        if not isinstance(values, Mapping) or len(values) > 40:
            raise ValidationFailed("technical must be an object with at most 40 fields")
        form = self.category(category)
        allowed = set(form["tech"]) if form else set()
        existing = dict(previous or {})
        result = dict(existing)
        for key, value in values.items():
            if key in {"anydeskId", "rmmAgentId"}:
                pattern = r"[0-9]{5,12}" if key == "anydeskId" else r"[A-Za-z0-9._-]{3,64}"
                if not isinstance(value, str) or (value and re.fullmatch(pattern, value) is None):
                    raise ValidationFailed(f"technical.{key} is not a valid remote identifier")
                result[key] = value
                continue
            if key in existing and value == existing[key]:
                result[key] = deepcopy(value)
                continue
            entry = self._entry("fields", key) if isinstance(key, str) else None
            if entry is None or key not in allowed or not entry.payload["active"]:
                raise ValidationFailed(f"technical field {key} is not active for this category")
            result[key] = field_value(entry.payload, value)
        for key in allowed:
            entry = self._entry("fields", key)
            if entry is None or not entry.payload["active"]:
                continue
            field = entry.payload
            if key not in result and defaults and "default" in field:
                result[key] = deepcopy(field["default"])
            if field.get("required") and result.get(key) is None:
                raise ValidationFailed(f"{key} is required")
        if len(result) > 40:
            raise ValidationFailed("technical must contain at most 40 fields")
        return result

    def _transitions(self, value: Any) -> dict[str, list[str]] | None:
        if value is None:
            return None
        if not isinstance(value, dict) or len(value) > 64:
            raise ValidationFailed("transitions must be an object with at most 64 states")
        result = {}
        for old, targets in value.items():
            if self._entry("statuses", old) is None:
                raise ValidationFailed("transition source does not exist")
            result[old] = keys(targets, "transition targets", limit=64)
            if any(self._entry("statuses", new) is None for new in result[old]):
                raise ValidationFailed("transition target does not exist")
        return result

    def _field(self, payload: dict[str, Any]) -> dict[str, Any]:
        allowed = {
            "key",
            "label",
            "labels",
            "type",
            "active",
            "required",
            "unit",
            "hint",
            "options",
            "default",
            "minimum",
            "maximum",
            "maxLength",
        }
        self._unknown(payload, allowed)
        kind = payload.get("type", "text")
        if not isinstance(kind, str) or kind not in FIELD_TYPES:
            raise ValidationFailed("unsupported field type")
        label_text, labels = self._label_pair(payload)
        result = dict(
            key=payload["key"],
            label=label_text,
            type=kind,
            active=boolean(payload.get("active", True), "active"),
            required=boolean(payload.get("required", False), "required"),
            unit=text(payload["unit"], "unit", 24) if payload.get("unit") else "",
            hint=text(payload["hint"], "hint", 500) if payload.get("hint") else "",
            options=keys(payload.get("options", []), "options"),
        )
        length = payload.get("maxLength", 500)
        if isinstance(length, bool) or not isinstance(length, int) or not 1 <= length <= 500:
            raise ValidationFailed("maxLength must be between 1 and 500")
        result["maxLength"] = length
        if labels:
            result["labels"] = labels
        if kind == "select" and not result["options"]:
            raise ValidationFailed("select requires options")
        for bound in ("minimum", "maximum"):
            if payload.get(bound) is not None:
                result[bound] = number(payload[bound], bound)
        if result.get("minimum", -(10**12)) > result.get("maximum", 10**12):
            raise ValidationFailed("minimum exceeds maximum")
        if "default" in payload:
            result["default"] = field_value(result, payload["default"])
        return result

    @staticmethod
    def _unknown(payload: dict[str, Any], allowed: set[str]) -> None:
        if set(payload) - allowed:
            raise ValidationFailed("unsupported configuration fields")

    def _category(self, payload: dict[str, Any]) -> dict[str, Any]:
        self._unknown(
            payload,
            {
                "id",
                "label",
                "labels",
                "prefix",
                "type",
                "icon",
                "active",
                "fov",
                "quick",
                "advanced",
                "tech",
                "transitions",
            },
        )
        prefix = text(payload.get("prefix", "OTRO"), "prefix", 6).upper()
        if not re.fullmatch(r"[A-Z0-9]+", prefix):
            raise ValidationFailed("prefix must contain letters and digits only")
        label_text, labels = self._label_pair(payload, limit=64)
        result = dict(
            id=payload["id"],
            label=label_text,
            prefix=prefix,
            type=text(payload.get("type", "Equipo"), "type", 64),
            icon=text(payload.get("icon", "box"), "icon", 32),
            active=boolean(payload.get("active", True), "active"),
            fov=boolean(payload.get("fov", False), "fov"),
        )
        if labels:
            result["labels"] = labels
        for group in ("quick", "advanced", "tech"):
            result[group] = keys(payload.get(group, []), group)
        if set(result["quick"]) & set(result["advanced"]):
            raise ValidationFailed("a common field cannot be both quick and advanced")
        if set(result["quick"] + result["advanced"]) - set(COMMON_KEYS):
            raise ValidationFailed("unknown common form field")
        if any(self._entry("fields", key) is None for key in result["tech"]):
            raise ValidationFailed("unknown technical form field")
        result["transitions"] = self._transitions(payload.get("transitions"))
        return result

    def _status(self, payload: dict[str, Any]) -> dict[str, Any]:
        self._unknown(payload, {"id", "label", "labels", "tone", "final", "active"})
        tone = payload.get("tone", "ok")
        if not isinstance(tone, str) or tone not in {"ok", "hold", "warn", "down"}:
            raise ValidationFailed("unsupported status tone")
        label_text, labels = self._label_pair(payload)
        result = dict(
            id=payload["id"],
            label=label_text,
            tone=tone,
            final=boolean(payload.get("final", False), "final"),
            active=boolean(payload.get("active", True), "active"),
        )
        if labels:
            result["labels"] = labels
        return result

    def _rule(self, key: str, payload: dict[str, Any], old: dict[str, Any]) -> dict[str, Any]:
        if key == "transitions":
            self._unknown(payload, {"id", "transitions"})
            return dict(id=key, transitions=self._transitions(payload.get("transitions")))
        if key != "identification":
            raise NotFound("unknown identification rule")
        self._unknown(
            payload,
            {"id", "separator", "quickPad", "siteCodeLength", "includeSite", "order", "siteCodes"},
        )
        result = {**old, **payload, "id": key}
        if not isinstance(result["separator"], str) or result["separator"] not in {"-", "_", "."}:
            raise ValidationFailed("unsupported quick code separator")
        for name, minimum, maximum in [("quickPad", 2, 5), ("siteCodeLength", 2, 5)]:
            value = result[name]
            if (
                isinstance(value, bool)
                or not isinstance(value, int)
                or not minimum <= value <= maximum
            ):
                raise ValidationFailed(f"{name} must be between {minimum} and {maximum}")
        result["includeSite"] = boolean(result["includeSite"], "includeSite")
        if not isinstance(result["order"], str) or result["order"] not in {
            "site-type",
            "type-site",
        }:
            raise ValidationFailed("unsupported code component order")
        codes = result["siteCodes"]
        if not isinstance(codes, dict) or len(codes) > 200:
            raise ValidationFailed("siteCodes must contain at most 200 abbreviations")
        for site, code in codes.items():
            text(site, "site", 120)
            if not isinstance(code, str) or not re.fullmatch(r"[A-Za-z0-9]{1,5}", code):
                raise ValidationFailed("site code must be 1-5 letters or digits")
        result["siteCodes"] = {site: code.upper() for site, code in codes.items()}
        return result

    def put(
        self, principal: Principal, kind: str, key: str, payload: Mapping[str, Any]
    ) -> dict[str, Any]:
        """Upsert one bounded metadata record; no delete or destructive retyping."""
        permission = "config.categories" if kind in {"fields", "categories"} else "config.general"
        self.identity.authorize(principal, permission, resource=f"inventory:config:{kind}:{key}")
        if kind not in _KINDS or not isinstance(key, str) or not _KEY.fullmatch(key):
            raise ValidationFailed("invalid configuration kind or key")
        if not isinstance(payload, Mapping):
            raise ValidationFailed("configuration must be an object")
        data = dict(payload)
        identity_key = "key" if kind == "fields" else "id"
        if data.get(identity_key, key) != key:
            raise ValidationFailed("configuration key is immutable")
        data[identity_key] = key
        entry = self._entry(kind, key)
        old = deepcopy(entry.payload) if entry else {}
        if kind == "fields":
            checked = self._field(data)
            if old and (
                checked["type"] != old["type"] or not set(old["options"]) <= set(checked["options"])
            ):
                raise Conflict("field types and existing options are immutable; create a new field")
            if old and (
                checked.get("minimum", -(10**12)) > old.get("minimum", -(10**12))
                or checked.get("maximum", 10**12) < old.get("maximum", 10**12)
                or checked["maxLength"] < old["maxLength"]
                or (checked["required"] and not old["required"])
            ):
                raise Conflict("existing field validation cannot be narrowed")
        elif kind == "categories":
            checked = self._category(data)
            if any(
                item["id"] != key and item["label"].casefold() == checked["label"].casefold()
                for item in self._items("categories")
            ):
                raise Conflict("category label already exists")
        elif kind == "statuses":
            if len(key) > 24:
                raise ValidationFailed("status id must contain at most 24 characters")
            checked = self._status(data)
        else:
            checked = self._rule(key, data, old)
        if entry is None:
            self.session.add(InventoryCatalogEntry(kind=kind, key=key, payload=checked))
        else:
            entry.payload = checked
        try:
            self.session.flush()
        except IntegrityError:
            self.session.rollback()
            raise Conflict("configuration changed concurrently; reload and retry") from None
        self.identity.record_operation(
            principal, action="inventory.config_updated", resource=f"inventory:config:{kind}:{key}"
        )
        return self._rendered(checked)
