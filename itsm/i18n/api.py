"""Public catalog endpoints, localized docs and the installation settings."""

from __future__ import annotations

from typing import Annotated, Any

from fastapi import APIRouter, Query, Request, Response
from fastapi.responses import JSONResponse
from pydantic import BaseModel, ConfigDict, Field

from itsm.i18n import registry
from itsm.i18n.envelope import error_payload
from itsm.i18n.messages import t
from itsm.i18n.request import resolve_request_locale
from itsm.i18n.settings import InstallationSettings, read_installation_settings
from itsm.identity.api import AuthDependency, MutationDependency, ServiceDependency

NO_STORE = {"Cache-Control": "no-store"}
REVALIDATE = {"Cache-Control": "no-cache"}


class InstallationSettingsRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    defaultLocale: str = Field(min_length=2, max_length=35)
    timezone: str = Field(min_length=1, max_length=64)
    currency: str = Field(min_length=3, max_length=3)


def locales_payload(
    installation: InstallationSettings, snapshot: registry.Snapshot
) -> dict[str, Any]:
    """The D11 selector payload: revision, installation formats and providers."""
    return {
        "revision": snapshot.revision,
        "defaultLocale": installation.default_locale,
        "formats": {"timezone": installation.timezone, "currency": installation.currency},
        "locales": [dict(descriptor) for descriptor in snapshot.descriptors],
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


def _not_found(request: Request, key: str, **params: str) -> JSONResponse:
    locale = resolve_request_locale(request)
    return JSONResponse(
        status_code=404,
        content=error_payload(
            "not_found",
            t(key, locale, **params),
            key=key,
            params=dict(params),
        ),
    )


def create_i18n_router() -> APIRouter:
    router = APIRouter()

    @router.get("/i18n/locales")
    def locales(request: Request) -> JSONResponse:
        """Public: which languages and installation formats are available."""
        with request.app.state.session_factory() as session:
            installation = read_installation_settings(session)
            snapshot = registry.snapshot(session)
        return JSONResponse(content=locales_payload(installation, snapshot))

    @router.get("/i18n/bundle")
    def bundle(
        request: Request,
        locale: Annotated[str, Query(min_length=1, max_length=35)],
    ) -> Response:
        """Public: the resolved messages for one installed locale, ETag revalidated."""
        with request.app.state.session_factory() as session:
            installation = read_installation_settings(session)
            snapshot = registry.snapshot(session)
        resolved = snapshot.resolve(locale)
        if resolved is None:
            return _not_found(request, "api.i18n.unknown_locale", locale=locale)
        view = snapshot.locale_view(resolved)
        etag = f'"{snapshot.revision}-{view.tag}"'
        if _etag_matches(request.headers.get("if-none-match"), etag):
            return Response(status_code=304, headers={"ETag": etag})
        return JSONResponse(
            content={
                "locale": view.tag,
                "revision": snapshot.revision,
                "fallback": [
                    snapshot.display_tag(tag)
                    for tag in snapshot.fallback(resolved, installation.default_locale)
                ],
                "messages": dict(view.messages),
                "overrides": dict(view.overrides),
            },
            headers={"ETag": etag, **REVALIDATE},
        )

    @router.get("/i18n/docs")
    def docs(
        request: Request,
        context: AuthDependency,
        locale: Annotated[str, Query(min_length=1, max_length=35)],
        topic: Annotated[str, Query(min_length=1, max_length=120)],
    ) -> JSONResponse:
        """Authenticated: one localized documentation topic from installed packs."""
        del context  # the dependency refreshes the session; the docs are public data
        with request.app.state.session_factory() as session:
            installation = read_installation_settings(session)
            hit = registry.resolve_doc(session, locale, topic, installation.default_locale)
        if hit is None:
            return _not_found(request, "api.i18n.unknown_doc_topic", locale=locale, topic=topic)
        return JSONResponse(
            content={
                "locale": hit.locale,
                "topic": hit.topic,
                "content": hit.content,
                "provider": hit.provider,
            },
            headers=REVALIDATE,
        )

    @router.put("/i18n/settings")
    def update_settings(
        request: Request,
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
        # The bundle payload embeds the fallback chain, so a new default locale
        # must invalidate every cached ETag instead of serving a stale 304.
        with request.app.state.session_factory() as session:
            registry.bump_revision(session)
            session.commit()
            snapshot = registry.snapshot(session)
        return JSONResponse(content=locales_payload(installation, snapshot), headers=NO_STORE)

    return router
