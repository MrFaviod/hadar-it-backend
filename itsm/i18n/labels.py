"""Admin-editable labels (S4/D9): a legacy string or a locale map.

Categories, statuses, typed fields and relationship types keep a permanent
id/key. Their visible label may stay a plain string (legacy, treated as source
text and kept valid) or become a map of installed locale tags. Resolution
follows D5: the requested locale, its parents, the installation default, ``es``
and finally the first available text. Ids never change with a language.
"""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any, Final

from itsm.i18n.catalog import DEFAULT_LOCALE, installed_locales, resolve_installed_locale
from itsm.i18n.messages import fallback_tags, t

#: A label is bounded: it is an admin-facing caption, not free document text.
LOCALE_MAP_LIMIT: Final[int] = 24


class LabelError(ValueError):
    """A label value is neither a legacy string nor a valid locale map."""


def _checked_text(value: Any, field: str, limit: int) -> str:
    if not isinstance(value, str):
        raise LabelError(f"{field} must be text or a locale map")
    normalized = value.strip()
    if not normalized or len(normalized) > limit:
        raise LabelError(f"{field} must be 1-{limit} characters")
    return normalized


def _checked_map(
    value: Mapping[Any, Any], field: str, limit: int, source_locale: str
) -> dict[str, str]:
    if len(value) > LOCALE_MAP_LIMIT:
        raise LabelError(f"{field} must define at most {LOCALE_MAP_LIMIT} locales")
    resolved: dict[str, str] = {}
    for tag, text in value.items():
        installed = resolve_installed_locale(tag) if isinstance(tag, str) else None
        if installed is None or installed not in installed_locales():
            raise LabelError(f"{field} locale {tag} is not installed")
        if installed in resolved:
            raise LabelError(f"{field} defines locale {installed} twice")
        resolved[installed] = _checked_text(text, f"{field} ({installed})", limit)
    if source_locale not in resolved:
        raise LabelError(f"{field} must define the {source_locale} label")
    return {tag: resolved[tag] for tag in sorted(resolved)}


def validate_label(
    value: Any,
    mapping: Any = None,
    *,
    field: str,
    limit: int,
    source_locale: str = DEFAULT_LOCALE,
) -> tuple[str, dict[str, str] | None]:
    """Return ``(source text, locale map or None)`` for either accepted form.

    ``value`` is the label itself (string or map) and ``mapping`` the explicit
    map field a read payload exposes. A read payload echoes the text already
    rendered for the request locale, so text that matches any mapped value is a
    no-op and any other text is a deliberate edit of the source locale.
    """
    if isinstance(value, Mapping):
        # A read payload carries the map in both fields; the label itself wins.
        resolved = _checked_map(value, field, limit, source_locale)
        return resolved[source_locale], resolved
    text = None if value is None else _checked_text(value, field, limit)
    if mapping is None:
        if text is None:
            raise LabelError(f"{field} must be text or a locale map")
        return text, None
    if mapping is not None and not isinstance(mapping, Mapping):
        raise LabelError(f"{field} locale map must be an object")
    if not mapping:
        # ``{}`` is what a legacy string reads back as: still a legacy string.
        return text if text is not None else "", None
    resolved = _checked_map(mapping, field, limit, source_locale)
    if text is not None and text not in resolved.values():
        resolved[source_locale] = text
    return resolved[source_locale], {tag: resolved[tag] for tag in sorted(resolved)}


def resolve_label(
    labels: Mapping[str, str] | str | None,
    locale: str | None,
    *,
    default_locale: str = DEFAULT_LOCALE,
) -> str:
    """Resolve a legacy string or a locale map to one text (D5 precedence)."""
    if isinstance(labels, str):
        return labels
    if not isinstance(labels, Mapping):
        return ""
    for tag in fallback_tags(locale or default_locale, default_locale):
        text = labels.get(tag)
        if isinstance(text, str) and text:
            return text
    for tag in sorted(labels):
        text = labels[tag]
        if isinstance(text, str) and text:
            return text
    return ""


def label_view(
    text: str,
    labels: Mapping[str, str] | None,
    locale: str | None,
    *,
    default_locale: str = DEFAULT_LOCALE,
) -> dict[str, Any]:
    """Public shape: resolved ``label`` plus the full map (``{}`` when legacy)."""
    stored = dict(labels or {})
    return {
        "label": resolve_label(stored or text, locale, default_locale=default_locale),
        "labels": stored,
    }


def state_label(
    prefix: str, key: str, locale: str | None, *, default_locale: str = DEFAULT_LOCALE
) -> str:
    """Catalog text for a fixed (non-editable) state id such as ``maintenance``."""
    return t(f"{prefix}.{key}", locale or default_locale, default_locale=default_locale)
