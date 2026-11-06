"""Translation: named parameters, Babel plural categories and fallback.

Message syntax (D2): named ``{parameter}`` placeholders; plural forms separated
by `` | `` in CLDR category order. The plural category always comes from Babel's
``Locale.plural_form``; this module only maps that category to a form index.

Lookup goes through the versioned registry (D5) so an installed pack is visible
to ``t()``; when no registry is configured the owner files remain the answer.
"""

from __future__ import annotations

import logging
import re
from functools import cache

from babel import Locale
from babel.core import UnknownLocaleError

from itsm.i18n import registry
from itsm.i18n.catalog import (
    DEFAULT_LOCALE,
    catalog_keys,
    load_catalog,
    resolve_installed_locale,
)
from itsm.i18n.packs import is_literal_json_message

logger = logging.getLogger("itsm.i18n")

#: Universal CLDR category order; a locale's used subset keeps this order.
PLURAL_CATEGORIES = ("zero", "one", "two", "few", "many", "other")

#: Babel does not expose a locale's used categories, so they are sampled from
#: its own plural rule. The samples cover every CLDR integer distinction.
_PLURAL_SAMPLE_COUNTS = (
    0,
    1,
    2,
    3,
    5,
    6,
    7,
    10,
    11,
    20,
    21,
    100,
    101,
    102,
    1000,
    10000,
    100000,
    1000000,
)

_PLACEHOLDER = re.compile(r"\{([A-Za-z_][A-Za-z0-9_]*)\}")
_missing_logged: set[str] = set()


@cache
def _babel_locale(tag: str | None) -> Locale | None:
    if not tag:
        return None
    try:
        return Locale.parse(tag.replace("-", "_"))
    except UnknownLocaleError, ValueError:
        return None


@cache
def plural_categories(locale: str) -> tuple[str, ...]:
    """Categories the locale's own plural rule can produce, in CLDR order."""
    parsed = _babel_locale(locale)
    if parsed is None:
        return ("other",)
    used = {parsed.plural_form(count) for count in _PLURAL_SAMPLE_COUNTS}
    return tuple(category for category in PLURAL_CATEGORIES if category in used) or ("other",)


def select_plural_form(template: str, locale: str, count: int | float) -> str:
    """Pick the form for ``count``; a short catalog reuses its last form."""
    forms = [form.strip() for form in template.split("|")]
    if len(forms) == 1:
        return forms[0]
    parsed = _babel_locale(locale)
    category = "other" if parsed is None else parsed.plural_form(count)
    categories = plural_categories(locale)
    index = categories.index(category) if category in categories else 0
    return forms[min(index, len(forms) - 1)]


def fallback_tags(
    locale: str | None, default_locale: str | None = DEFAULT_LOCALE
) -> tuple[str, ...]:
    """D5 chain: locale (with parents) -> installation default -> Spanish."""
    default = default_locale or DEFAULT_LOCALE
    snapshot = registry.current_snapshot()
    if snapshot is not None:
        return snapshot.fallback(locale, default)
    tags: list[str] = []
    for candidate in (locale, default, DEFAULT_LOCALE):
        for tag in registry.tag_chain(candidate):
            installed = resolve_installed_locale(tag)
            if installed is not None and installed not in tags:
                tags.append(installed)
    return tuple(tags)


def message_for(
    key: str, locale: str | None, default_locale: str | None = DEFAULT_LOCALE
) -> tuple[str | None, str | None]:
    hit = registry.lookup(key, locale, default_locale or DEFAULT_LOCALE)
    if hit is not None:
        return hit
    for tag in fallback_tags(locale, default_locale):
        catalog = load_catalog(tag)
        if catalog is not None and key in catalog:
            return catalog[key], tag
    return None, None


def render(template: str, locale: str, params: dict[str, object]) -> str:
    if is_literal_json_message(template):
        return template
    count = params.get("count")
    if isinstance(count, (int, float)) and not isinstance(count, bool) and "|" in template:
        template = select_plural_form(template, locale, count)
    return _PLACEHOLDER.sub(
        lambda match: str(params[match.group(1)]) if match.group(1) in params else match.group(0),
        template,
    )


def t(
    key: str,
    locale: str | None = None,
    /,
    *,
    default_locale: str = DEFAULT_LOCALE,
    **params: object,
) -> str:
    """Translate ``key``; a missing key never leaks as raw text.

    ``locale`` is positional-only so a message may itself use ``{locale}`` as a
    named parameter without colliding with the argument.
    """
    requested = locale or default_locale
    template, _ = message_for(key, requested, default_locale)
    if template is None:
        _log_missing_once(key, requested)
        template, _ = message_for("api.i18n.text_unavailable", requested, default_locale)
        if template is None:  # pragma: no cover - both core catalogs define it
            template = "Text unavailable."
    return render(template, requested, params)


def resolve_messages(locale: str, default_locale: str | None = DEFAULT_LOCALE) -> dict[str, str]:
    """The full message set for one locale, fallback applied per key."""
    fallback = default_locale or DEFAULT_LOCALE
    snapshot = registry.current_snapshot()
    resolved = registry.resolve_installed(locale)
    if snapshot is not None and resolved is not None:
        return dict(snapshot.locale_view(resolved).messages)
    return {key: t(key, locale, default_locale=fallback) for key in sorted(catalog_keys())}


def _log_missing_once(key: str, locale: str) -> None:
    if key in _missing_logged:
        return
    _missing_logged.add(key)
    logger.warning("missing translation key %s for locale %s", key, locale)
