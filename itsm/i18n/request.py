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
from itsm.i18n.catalog import DEFAULT_LOCALE
from itsm.i18n.registry import installed_tags, resolve_installed
from itsm.i18n.settings import InstallationSettings, read_installation_settings

logger = logging.getLogger("itsm.i18n")


def _quality(parameters: list[str]) -> float:
    """The ``q`` weight of one range; an unparsable weight is excluded."""
    for parameter in parameters:
        name, _, value = parameter.partition("=")
        if name.strip().lower() != "q":
            continue
        try:
            return float(value.strip())
        except ValueError:
            return 0.0
    return 1.0


def negotiated_preferences(header: str | None) -> tuple[str, ...]:
    """Ranges in preference order: highest ``q`` first, ties keep header order.

    D8 delegates negotiation to Babel, but RFC 4647 attaches a quality weight to
    every range: ``q=0`` means "not acceptable" and ``en;q=0.9`` must beat
    ``es;q=0.1``. Babel's ``negotiate`` only sees an ordered list, so the header
    is weighted here before the standard matcher runs.
    """
    if not header:
        return ()
    weighted: list[tuple[float, int, str]] = []
    for index, part in enumerate(header.split(",")):
        pieces = part.split(";")
        tag = pieces[0].strip().replace("-", "_")
        if not tag or tag == "*":
            continue
        quality = _quality(pieces[1:])
        if quality <= 0:
            continue
        weighted.append((quality, index, tag))
    weighted.sort(key=lambda item: (-item[0], item[1]))
    return tuple(tag for _quality, _index, tag in weighted)


def negotiate_accept_language(
    header: str | None, available: tuple[str, ...] | None = None
) -> str | None:
    """Match an ``Accept-Language`` header against installed locales via Babel."""
    preferred = list(negotiated_preferences(header))
    if not preferred:
        return None
    installed = list(installed_tags() if available is None else available)
    # Header ranges are compared with ``_`` separators; installed pack tags such
    # as ``pt-br`` must use the same separator or Babel never matches them.
    candidates = {tag.replace("-", "_").lower(): tag for tag in installed}
    try:
        matched = Locale.negotiate(preferred, list(candidates), sep="_")
    except TypeError, ValueError:
        return None
    if not matched:
        return None
    tag = candidates.get(str(matched).lower(), str(matched))
    # An explicit ``available`` list is authoritative when the registry does not
    # know the tag yet (callers negotiating against a candidate pack).
    return resolve_installed(tag) or (tag if available is not None else None)


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
        resolve_installed(preference)
        or negotiate_accept_language(request.headers.get("accept-language"))
        or resolve_installed(installation.default_locale)
        or DEFAULT_LOCALE
    )
    request.state.locale = locale
    return locale
