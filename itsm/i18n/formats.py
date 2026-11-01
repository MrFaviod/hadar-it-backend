"""Locale-aware formatting for documents and notifications (later tasks)."""

from __future__ import annotations

from datetime import date, datetime, time
from typing import Any

from babel.core import get_global
from babel.dates import format_datetime as _format_datetime
from babel.dates import get_timezone
from babel.numbers import format_currency as _format_currency
from babel.numbers import format_decimal

from itsm.i18n.catalog import DEFAULT_LOCALE


def _identifier(locale: str | None) -> str:
    return (locale or DEFAULT_LOCALE).replace("-", "_")


def format_number(value: int | float, locale: str | None = None) -> str:
    return format_decimal(value, locale=_identifier(locale))


def format_currency(
    value: int | float, locale: str | None = None, currency: str | None = None
) -> str:
    if not currency:
        raise ValueError("an installation currency is required")
    return _format_currency(value, currency, locale=_identifier(locale))


def format_datetime(
    value: datetime | date | time, locale: str | None = None, timezone: str | None = None
) -> str:
    if not timezone:
        raise ValueError("an installation time zone is required")
    return _format_datetime(value, locale=_identifier(locale), tzinfo=get_timezone(timezone))


def is_valid_timezone(name: str | None) -> bool:
    if not name:
        return False
    try:
        get_timezone(name)
    except LookupError, ValueError:
        return False
    return True


def is_valid_currency(code: str | None) -> bool:
    if not code or len(code) != 3 or not code.isalpha():
        return False
    return code.upper() in get_global("all_currencies")


def as_number(value: Any) -> int | float:
    """Narrow a JSON number for the formatting helpers above."""
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise ValueError("a number is required")
    return value
