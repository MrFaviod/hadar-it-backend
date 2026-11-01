"""Installation i18n preferences stored in the existing identity settings row.

The singleton ``identity_security_settings`` row already holds installation-wide
policy, so the default locale, time zone and currency live there instead of a
second settings table. Absence of the row means "no administrator changed the
defaults yet", which is why the defaults are also applied at read time.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING, Any

from itsm.i18n.catalog import DEFAULT_LOCALE, resolve_installed_locale
from itsm.i18n.formats import is_valid_currency, is_valid_timezone

if TYPE_CHECKING:
    from sqlalchemy.orm import Session

DEFAULT_TIMEZONE = "America/Asuncion"
DEFAULT_CURRENCY = "PYG"


@dataclass(frozen=True)
class InstallationSettings:
    default_locale: str = DEFAULT_LOCALE
    timezone: str = DEFAULT_TIMEZONE
    currency: str = DEFAULT_CURRENCY

    def as_payload(self) -> dict[str, str]:
        return {
            "defaultLocale": self.default_locale,
            "timezone": self.timezone,
            "currency": self.currency,
        }


class InstallationSettingError(ValueError):
    """An installation value is invalid; carries the stable message key."""

    def __init__(self, message: str, *, key: str, params: dict[str, Any]) -> None:
        super().__init__(message)
        self.key = key
        self.params = dict(params)


def read_installation_settings(session: Session) -> InstallationSettings:
    from itsm.identity.models import IdentitySecuritySettings

    row = session.get(IdentitySecuritySettings, 1)
    if row is None:
        return InstallationSettings()
    return InstallationSettings(
        default_locale=resolve_installed_locale(row.default_locale) or DEFAULT_LOCALE,
        timezone=row.timezone or DEFAULT_TIMEZONE,
        currency=row.currency or DEFAULT_CURRENCY,
    )


def validate_installation_settings(
    *, default_locale: str, timezone: str, currency: str
) -> InstallationSettings:
    locale = resolve_installed_locale(default_locale)
    if locale is None:
        raise InstallationSettingError(
            f"unknown locale: {default_locale}",
            key="api.i18n.unknown_locale",
            params={"locale": default_locale},
        )
    zone = (timezone or "").strip()
    if not is_valid_timezone(zone):
        raise InstallationSettingError(
            f"invalid time zone: {zone}",
            key="api.i18n.invalid_timezone",
            params={"timezone": timezone},
        )
    code = (currency or "").strip().upper()
    if not is_valid_currency(code):
        raise InstallationSettingError(
            f"invalid currency: {currency}",
            key="api.i18n.invalid_currency",
            params={"currency": currency},
        )
    return InstallationSettings(default_locale=locale, timezone=zone, currency=code)
