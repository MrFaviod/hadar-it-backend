"""Request locale resolution (D8): user preference -> Accept-Language -> default.

Resolution is read-only and cached on ``request.state.locale`` so the error
handlers can use the same answer as the route. It never refreshes or commits a
session; authentication itself stays in the identity service.
"""

from __future__ import annotations

import logging

from babel import Locale
from fastapi import Request

from itsm.config import Settings
from itsm.i18n.catalog import CORE_LOCALES, DEFAULT_LOCALE, resolve_installed_locale
from itsm.i18n.settings import InstallationSettings, read_installation_settings

logger = logging.getLogger("itsm.i18n")


def negotiate_accept_language(
    header: str | None, available: tuple[str, ...] = CORE_LOCALES
) -> str | None:
    """Match an ``Accept-Language`` header against installed locales via Babel."""
    if not header:
        return None
    preferred: list[str] = []
    for part in header.split(","):
        tag = part.split(";")[0].strip().replace("-", "_")
        if not tag or tag == "*":
            continue
        preferred.append(tag)
    if not preferred:
        return None
    try:
        matched = Locale.negotiate(preferred, list(available), sep="_")
    except TypeError, ValueError:
        return None
    return resolve_installed_locale(matched) if matched else None


def resolve_request_locale(request: Request) -> str:
    """The effective locale for this request, cached for handlers and errors."""
    cached = getattr(request.state, "locale", None)
    if cached:
        return str(cached)

    installation = InstallationSettings()
    preference: str | None = None
    state = getattr(request.app, "state", None)
    settings: Settings | None = getattr(state, "settings", None)
    factory = getattr(state, "session_factory", None)
    if factory is not None and settings is not None:
        try:
            from itsm.identity.service import IdentityService

            with factory() as session:
                installation = read_installation_settings(session)
                token = request.cookies.get(settings.auth_cookie_name)
                if token:
                    preference = IdentityService(session, settings).locale_for_session(token)
        except Exception:
            logger.debug("locale resolution fell back to defaults", exc_info=True)
            installation = InstallationSettings()
            preference = None

    locale = (
        resolve_installed_locale(preference)
        or negotiate_accept_language(request.headers.get("accept-language"))
        or resolve_installed_locale(installation.default_locale)
        or DEFAULT_LOCALE
    )
    request.state.locale = locale
    return locale
