"""Core i18n: catalogs, translation, locale negotiation and formatting.

This package is a thin layer over Babel. It owns message lookup, the fallback
chain and request-locale resolution; plural rules, time zones and currency data
come from Babel itself. See ``docs/i18n.md`` for the contract.
"""

from itsm.i18n.catalog import (
    CATALOG_DIR,
    CORE_LOCALES,
    DEFAULT_LOCALE,
    catalog_keys,
    installed_locales,
    load_catalog,
    locale_descriptor,
    resolve_installed_locale,
)
from itsm.i18n.envelope import error_payload
from itsm.i18n.formats import (
    format_currency,
    format_datetime,
    format_number,
    is_valid_currency,
    is_valid_timezone,
)
from itsm.i18n.messages import fallback_tags, resolve_messages, t
from itsm.i18n.request import negotiate_accept_language, resolve_request_locale
from itsm.i18n.settings import (
    DEFAULT_CURRENCY,
    DEFAULT_TIMEZONE,
    InstallationSettingError,
    InstallationSettings,
    read_installation_settings,
    validate_installation_settings,
)

__all__ = [
    "CATALOG_DIR",
    "CORE_LOCALES",
    "DEFAULT_CURRENCY",
    "DEFAULT_LOCALE",
    "DEFAULT_TIMEZONE",
    "InstallationSettingError",
    "InstallationSettings",
    "catalog_keys",
    "error_payload",
    "fallback_tags",
    "format_currency",
    "format_datetime",
    "format_number",
    "installed_locales",
    "is_valid_currency",
    "is_valid_timezone",
    "load_catalog",
    "locale_descriptor",
    "negotiate_accept_language",
    "read_installation_settings",
    "resolve_installed_locale",
    "resolve_messages",
    "resolve_request_locale",
    "t",
    "validate_installation_settings",
]
