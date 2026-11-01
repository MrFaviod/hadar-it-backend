"""Document and outbound-message localization: one language per artifact.

Reports, spreadsheets, labels and notifications do not inherit the request
locale. A document is rendered in the language the requester asked for and a
notification in the effective language of each recipient. Time zone and currency
always come from the installation, so choosing English never changes the money
or the clock (D7); only the wording and the number/date conventions follow the
artifact's own locale.
"""

from __future__ import annotations

import re
from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from datetime import date, datetime
from decimal import Decimal, InvalidOperation
from typing import TYPE_CHECKING, Any

from babel.dates import format_date as _format_date

from itsm.i18n.catalog import DEFAULT_LOCALE, resolve_installed_locale
from itsm.i18n.formats import format_currency, format_datetime, format_number
from itsm.i18n.messages import render, t
from itsm.i18n.settings import (
    DEFAULT_CURRENCY,
    DEFAULT_TIMEZONE,
    InstallationSettings,
    read_installation_settings,
)

if TYPE_CHECKING:
    from sqlalchemy.orm import Session

#: A stored message key is a catalog identifier, never caller-authored text.
MAX_KEY_LENGTH = 120
MAX_PARAMS = 20
MAX_PARAM_CHARS = 500

_PARAM_NAME = re.compile(r"^[a-z_][a-z0-9_]{0,40}$")
_ISO_DAY = re.compile(r"^\d{4}-\d{2}-\d{2}$")


class LocaleUnavailable(ValueError):
    """A requested document locale is not installed; carries the stable key."""

    def __init__(self, locale: str) -> None:
        super().__init__(f"unknown locale: {locale}")
        self.key = "api.i18n.unknown_locale"
        self.params: dict[str, Any] = {"locale": locale}


def normalize_params(params: Mapping[str, Any] | None) -> dict[str, object]:
    """Bounded, JSON-safe parameters for one stored message key."""
    if not params:
        return {}
    if not isinstance(params, Mapping):
        raise ValueError("message parameters must be a mapping")
    if len(params) > MAX_PARAMS:
        raise ValueError(f"message parameters exceed {MAX_PARAMS} entries")
    normalized: dict[str, object] = {}
    for name, value in params.items():
        if not isinstance(name, str) or _PARAM_NAME.fullmatch(name) is None:
            raise ValueError("message parameter names must be lowercase identifiers")
        if isinstance(value, bool) or value is None or isinstance(value, (int, float)):
            normalized[name] = value
        elif isinstance(value, str):
            normalized[name] = value[:MAX_PARAM_CHARS]
        else:
            raise ValueError("message parameters must be scalars")
    return normalized


def normalize_key(key: str) -> str:
    """Validate one stored key; catalog lookup itself is the authority."""
    if not isinstance(key, str) or not key.strip() or len(key) > MAX_KEY_LENGTH:
        raise ValueError(f"message key must be 1-{MAX_KEY_LENGTH} characters")
    normalized = key.strip()
    if not normalized.replace(".", "").replace("_", "").isalnum():
        raise ValueError("message key must be a dotted catalog identifier")
    return normalized


def render_message(
    key: str,
    params: Mapping[str, Any] | None = None,
    locale: str | None = None,
    *,
    default_locale: str = DEFAULT_LOCALE,
) -> str:
    """Render one key in ``locale``; a missing key never leaks as raw text."""
    return t(
        key,
        locale or default_locale,
        default_locale=default_locale,
        **normalize_params(params),
    )


def render_template(
    template: str,
    params: Mapping[str, Any] | None,
    locale: str,
) -> str:
    """Render an already resolved catalog template (used for CSS fragments)."""
    return render(template, locale, normalize_params(params))


@dataclass(frozen=True)
class DocumentLocale:
    """The locale of one rendered artifact plus the installation formats."""

    locale: str = DEFAULT_LOCALE
    timezone: str = DEFAULT_TIMEZONE
    currency: str = DEFAULT_CURRENCY
    default_locale: str = DEFAULT_LOCALE

    def t(self, key: str, /, **params: object) -> str:
        return t(key, self.locale, default_locale=self.default_locale, **params)

    def number(self, value: Any) -> str:
        amount = _number(value)
        return str(value) if amount is None else format_number(amount, self.locale)

    def money(self, value: Any) -> str:
        amount = _number(value)
        if amount is None:
            return str(value)
        return format_currency(amount, self.locale, self.currency)

    def day(self, value: Any) -> str:
        moment = _day(value)
        return str(value) if moment is None else _format_date(moment, locale=self.locale)

    def moment(self, value: Any) -> str:
        if isinstance(value, str) and _ISO_DAY.fullmatch(value.strip()):
            return self.day(value)
        instant = _instant(value)
        if instant is None:
            return str(value)
        return format_datetime(instant, self.locale, self.timezone)

    def as_payload(self) -> dict[str, str]:
        return {
            "locale": self.locale,
            "timezone": self.timezone,
            "currency": self.currency,
        }


def default_document_locale() -> DocumentLocale:
    """Spanish with the shipped installation defaults; used without a session."""
    return DocumentLocale()


def document_locale(
    installation: InstallationSettings,
    *,
    locale: str | None = None,
    identity_locale: str | None = None,
) -> DocumentLocale:
    """One artifact's locale: explicit, else the requester's, else the default."""
    resolved = resolve_installed_locale(locale)
    if locale is not None and resolved is None:
        raise LocaleUnavailable(locale)
    chosen = (
        resolved
        or resolve_installed_locale(identity_locale)
        or resolve_installed_locale(installation.default_locale)
        or DEFAULT_LOCALE
    )
    return DocumentLocale(
        locale=chosen,
        timezone=installation.timezone,
        currency=installation.currency,
        default_locale=installation.default_locale,
    )


def read_document_locale(
    session: Session | None = None,
    *,
    locale: str | None = None,
    identity_id: str | None = None,
) -> DocumentLocale:
    """Resolve a document locale from persisted state, never from a header."""
    installation = (
        InstallationSettings() if session is None else read_installation_settings(session)
    )
    stored = identity_locale(session, identity_id) if session is not None else None
    return document_locale(installation, locale=locale, identity_locale=stored)


def identity_locale(session: Session, identity_id: str | None) -> str | None:
    """One identity's own preference, or ``None`` when it follows the installation."""
    if not identity_id:
        return None
    from sqlalchemy import select

    from itsm.identity.models import Identity

    stored = session.execute(
        select(Identity.locale).where(Identity.id == identity_id)
    ).scalar_one_or_none()
    return resolve_installed_locale(stored)


def recipient_locales(session: Session, identity_ids: Iterable[str | None]) -> dict[str, str]:
    """Effective locale per recipient: own preference, else the installation default."""
    installation = read_installation_settings(session)
    wanted = sorted({value for value in identity_ids if isinstance(value, str) and value})
    stored: dict[str, str] = {}
    if wanted:
        from sqlalchemy import select

        from itsm.identity.models import Identity

        for identity_id, locale in session.execute(
            select(Identity.id, Identity.locale).where(Identity.id.in_(wanted))
        ):
            resolved = resolve_installed_locale(locale)
            if resolved is not None:
                stored[identity_id] = resolved
    default = resolve_installed_locale(installation.default_locale) or DEFAULT_LOCALE
    return {identity_id: stored.get(identity_id, default) for identity_id in wanted}


def notification_document(session: Session, locale: str | None = None) -> DocumentLocale:
    """Document locale for an external channel with no individual recipient."""
    installation = read_installation_settings(session)
    return document_locale(installation, locale=locale)


def localized_message(
    session: Session | None,
    key: str,
    *,
    identity_id: str | None = None,
    params: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    """One user-visible system message: stable key, parameters and its text.

    ``message`` is rendered in the locale of ``identity_id`` when that identity
    exists and otherwise in the installation default. Callers that already hold
    a principal use it, so an asynchronous result keeps the requester's language.
    """
    checked_key = normalize_key(key)
    checked_params = normalize_params(params)
    document = read_document_locale(session, identity_id=identity_id)
    return {
        "key": checked_key,
        "params": checked_params,
        "locale": document.locale,
        "message": document.t(checked_key, **checked_params),
    }


def _number(value: Any) -> Decimal | None:
    if isinstance(value, bool):
        return None
    if isinstance(value, (int, float, Decimal)):
        return Decimal(str(value))
    if isinstance(value, str):
        text = value.strip().replace(",", "")
        if not text:
            return None
        try:
            return Decimal(text)
        except InvalidOperation:
            return None
    return None


def _day(value: Any) -> date | None:
    if isinstance(value, datetime):
        return value.date()
    if isinstance(value, date):
        return value
    if isinstance(value, str) and _ISO_DAY.fullmatch(value.strip()):
        try:
            return date.fromisoformat(value.strip())
        except ValueError:
            return None
    return None


def _instant(value: Any) -> datetime | None:
    if isinstance(value, datetime):
        return value
    if isinstance(value, date):
        return datetime(value.year, value.month, value.day)
    if isinstance(value, str):
        try:
            return datetime.fromisoformat(value.strip())
        except ValueError:
            return None
    return None


__all__ = [
    "MAX_KEY_LENGTH",
    "MAX_PARAMS",
    "DocumentLocale",
    "LocaleUnavailable",
    "default_document_locale",
    "document_locale",
    "identity_locale",
    "localized_message",
    "normalize_key",
    "normalize_params",
    "notification_document",
    "read_document_locale",
    "recipient_locales",
    "render_message",
    "render_template",
]
