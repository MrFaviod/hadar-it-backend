"""Public catalog endpoints and the installation i18n settings endpoint."""

from __future__ import annotations

from typing import Annotated, Any

from fastapi import APIRouter, Query, Request, Response
from fastapi.responses import JSONResponse
from pydantic import BaseModel, ConfigDict, Field

from itsm.i18n.catalog import installed_locales, locale_descriptor, resolve_installed_locale
from itsm.i18n.envelope import error_payload
from itsm.i18n.messages import fallback_tags, resolve_messages, t
from itsm.i18n.request import resolve_request_locale
from itsm.i18n.settings import InstallationSettings, read_installation_settings
from itsm.identity.api import MutationDependency, ServiceDependency

#: T1 serves the core catalog only; later packs bump this revision.
I18N_REVISION = 0

NO_STORE = {"Cache-Control": "no-store"}
REVALIDATE = {"Cache-Control": "no-cache"}


class InstallationSettingsRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    defaultLocale: str = Field(min_length=2, max_length=35)
    timezone: str = Field(min_length=1, max_length=64)
    currency: str = Field(min_length=3, max_length=3)


def locales_payload(installation: InstallationSettings) -> dict[str, Any]:
    return {
        "revision": I18N_REVISION,
        "defaultLocale": installation.default_locale,
        "formats": {"timezone": installation.timezone, "currency": installation.currency},
        "locales": [locale_descriptor(tag) for tag in installed_locales()],
    }


def _etag_matches(header: str | None, etag: str) -> bool:
    if not header:
        return False
    for candidate in header.split(","):
        value = candidate.strip()
        if value.startswith("W/"):
            value = value[2:]
        if value == etag or value == "*":
            return True
    return False


def create_i18n_router() -> APIRouter:
    router = APIRouter()

    @router.get("/i18n/locales")
    def locales(request: Request) -> JSONResponse:
        """Public: which languages and installation formats are available."""
        with request.app.state.session_factory() as session:
            installation = read_installation_settings(session)
        return JSONResponse(content=locales_payload(installation))

    @router.get("/i18n/bundle")
    def bundle(
        request: Request,
        locale: Annotated[str, Query(min_length=1, max_length=35)],
    ) -> Response:
        """Public: the core messages for one installed locale, ETag revalidated."""
        resolved = resolve_installed_locale(locale)
        if resolved is None:
            request_locale = resolve_request_locale(request)
            return JSONResponse(
                status_code=404,
                content=error_payload(
                    "not_found",
                    t("api.i18n.unknown_locale", request_locale, locale=locale),
                    key="api.i18n.unknown_locale",
                    params={"locale": locale},
                ),
            )
        with request.app.state.session_factory() as session:
            installation = read_installation_settings(session)
        etag = f'"{I18N_REVISION}-{resolved}"'
        if _etag_matches(request.headers.get("if-none-match"), etag):
            return Response(status_code=304, headers={"ETag": etag})
        return JSONResponse(
            content={
                "locale": resolved,
                "revision": I18N_REVISION,
                "fallback": list(fallback_tags(resolved, installation.default_locale)),
                "messages": resolve_messages(resolved, installation.default_locale),
                "overrides": {},
            },
            headers={"ETag": etag, **REVALIDATE},
        )

    @router.put("/i18n/settings")
    def update_settings(
        payload: InstallationSettingsRequest,
        context: MutationDependency,
        service: ServiceDependency,
    ) -> JSONResponse:
        """Installation defaults; ``system.configure`` is enforced by the service."""
        installation = service.update_installation_settings(
            context.principal,
            default_locale=payload.defaultLocale,
            timezone=payload.timezone,
            currency=payload.currency,
        )
        return JSONResponse(content=locales_payload(installation), headers=NO_STORE)

    return router
