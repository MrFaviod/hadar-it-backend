"""Public catalog endpoints, translator tools and installation settings."""

from __future__ import annotations

from typing import Annotated, Any

from fastapi import APIRouter, Query, Request, Response
from fastapi.responses import JSONResponse
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy.orm import Session

from itsm.demo.restrictions import visitor_password_waiver
from itsm.i18n import registry, tools
from itsm.i18n.envelope import error_payload
from itsm.i18n.messages import t
from itsm.i18n.request import resolve_request_locale
from itsm.i18n.settings import InstallationSettings, read_installation_settings
from itsm.identity.api import AuthDependency, MutationDependency, ServiceDependency
from itsm.identity.service import IdentityService

NO_STORE = {"Cache-Control": "no-store"}
REVALIDATE = {"Cache-Control": "no-cache"}


class InstallationSettingsRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    defaultLocale: str = Field(min_length=2, max_length=35)
    timezone: str = Field(min_length=1, max_length=64)
    currency: str = Field(min_length=3, max_length=3)


class UiSourceRequest(BaseModel):
    """The frontend ``ui.*`` source catalog, shipped per locale."""

    model_config = ConfigDict(extra="forbid")

    catalogs: dict[str, dict[str, str]] = Field(min_length=1)
    context: dict[str, str] = Field(default_factory=dict)


class CatalogRequest(BaseModel):
    """A posted catalog for validation or import into the custom layer."""

    model_config = ConfigDict(extra="forbid")

    locale: str = Field(min_length=2, max_length=35)
    format: str = Field(default="json", min_length=1, max_length=10)
    content: str = Field(min_length=1, max_length=2_000_000)


class ImportRequest(CatalogRequest):
    dryRun: bool = False


def _service_for(request: Request, session: Session) -> IdentityService:
    """An identity service bound to the registry transaction of this request.

    Authorizing and auditing on the *same* session keeps the audit row and the
    catalog rows in one commit: a rejected write leaves no audit for a mutation
    that never happened, and a stored mutation cannot lose its audit entry.
    """
    state = request.app.state
    capabilities = getattr(state, "release_capabilities", None)
    limits = getattr(state, "demo_limits", None)
    return IdentityService(
        session,
        state.settings,
        session_cap=None if limits is None else limits.session_cap,
        password_waiver=None if capabilities is None else visitor_password_waiver(capabilities),
    )


def _catalog_problem_response(
    request: Request,
    status: int,
    key: str,
    problems: list[tools.Problem],
    locale: str,
    report: dict[str, Any],
) -> JSONResponse:
    params = {"count": len(problems)}
    body = error_payload(
        "validation_error" if status == 422 else "bad_request",
        t(key, resolve_request_locale(request), **params),
        key=key,
        params=params,
    )
    body["report"] = {
        **report,
        "valid": False,
        "problems": tools.problems_payload(problems, locale),
    }
    return JSONResponse(status_code=status, content=body, headers=NO_STORE)


def _format_problem(request: Request, exc: tools.UnsupportedFormat) -> JSONResponse:
    return JSONResponse(
        status_code=422,
        content=error_payload(
            "validation_error",
            t("api.i18n.unsupported_format", resolve_request_locale(request), format=exc.format),
            key="api.i18n.unsupported_format",
            params={"format": exc.format},
        ),
        headers=NO_STORE,
    )


def _namespace_problem(request: Request, exc: tools.InvalidNamespace) -> JSONResponse:
    return JSONResponse(
        status_code=422,
        content=error_payload(
            "validation_error",
            t(
                "api.i18n.invalid_namespace",
                resolve_request_locale(request),
                namespace=exc.namespace,
            ),
            key="api.i18n.invalid_namespace",
            params={"namespace": exc.namespace},
        ),
        headers=NO_STORE,
    )


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


def _not_found(request: Request, message_key: str, **params: str) -> JSONResponse:
    locale = resolve_request_locale(request)
    return JSONResponse(
        status_code=404,
        content=error_payload(
            "not_found",
            t(message_key, locale, **params),
            key=message_key,
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

    # ------------------------------------------------------------ translator tools
    @router.put("/i18n/sources/ui")
    def register_ui_source(
        request: Request,
        payload: UiSourceRequest,
        context: MutationDependency,
    ) -> JSONResponse:
        """Register the frontend ``ui.*`` source catalog so coverage covers it.

        Idempotent by content hash: re-registering the same content keeps the
        revision (and therefore every bundle ETag) untouched. The registration is
        a *source* provider: it feeds coverage, validation and export, it is never
        overlaid onto served messages (the browser already ships its own catalog).
        """
        locale = resolve_request_locale(request)
        with request.app.state.session_factory() as session:
            identity = _service_for(request, session)
            identity.authorize(context.principal, "system.configure", resource="i18n:source:ui")
            catalogs, problems = tools.normalize_ui_source(payload.catalogs, payload.context)
            if problems:
                report = {
                    "source": tools.SOURCE_PROVIDER,
                    "entries": sum(len(catalog) for catalog in catalogs.values()),
                }
                return _catalog_problem_response(
                    request,
                    422,
                    "api.i18n.source_invalid",
                    problems,
                    locale,
                    report,
                )
            changed, digest = registry.write_source_catalog(
                session, tools.SOURCE_PROVIDER, catalogs, payload.context
            )
            if changed:
                identity.record_operation(
                    context.principal,
                    action="i18n.sources_registered",
                    resource="i18n:source:ui",
                    commit=False,
                )
            session.commit()
            revision = registry.revision(session)
        source_locale = tools.SOURCE_LOCALE
        ordered = [source_locale, *(tag for tag in sorted(catalogs) if tag != source_locale)]
        return JSONResponse(
            content={
                "source": tools.SOURCE_PROVIDER,
                "changed": changed,
                "digest": digest,
                "revision": revision,
                "locales": ordered,
                "keys": len(catalogs.get(source_locale, {})),
            },
            headers=NO_STORE,
        )

    @router.get("/i18n/coverage")
    def coverage(
        request: Request,
        context: AuthDependency,
        locale: Annotated[str | None, Query(min_length=1, max_length=35)] = None,
        namespace: Annotated[str | None, Query(min_length=1, max_length=200)] = None,
        limit: Annotated[int, Query(ge=1, le=tools.MAX_LIMIT)] = tools.DEFAULT_LIMIT,
        offset: Annotated[int, Query(ge=0)] = 0,
    ) -> JSONResponse:
        """Per installed locale: totals, missing keys with context and providers."""
        with request.app.state.session_factory() as session:
            identity = _service_for(request, session)
            identity.authorize(context.principal, "system.view", resource="i18n:coverage")
            try:
                prefix = tools.validate_namespace(namespace)
            except tools.InvalidNamespace as exc:
                return _namespace_problem(request, exc)
            try:
                report = tools.coverage_report(
                    session, locale=locale, namespace=prefix, limit=limit, offset=offset
                )
            except KeyError:
                return _not_found(request, "api.i18n.unknown_locale", locale=str(locale))
        return JSONResponse(content=report, headers=NO_STORE)

    @router.get("/i18n/export")
    def export(
        request: Request,
        context: AuthDependency,
        locale: Annotated[str, Query(min_length=1, max_length=35)],
        format: Annotated[str, Query(min_length=1, max_length=10)] = "json",
        namespace: Annotated[str | None, Query(min_length=1, max_length=200)] = None,
    ) -> Response:
        """Download one locale as ``{key: text}`` JSON or gettext PO (msgctxt = key)."""
        with request.app.state.session_factory() as session:
            identity = _service_for(request, session)
            identity.authorize(context.principal, "system.view", resource="i18n:export")
            snapshot = registry.snapshot(session)
            canonical = snapshot.resolve(locale)
            if canonical is None:
                return _not_found(request, "api.i18n.unknown_locale", locale=locale)
            try:
                body, media_type, filename = tools.export_document(
                    session, canonical, namespace=namespace, format_name=format
                )
            except tools.UnsupportedFormat as exc:
                return _format_problem(request, exc)
            except tools.InvalidNamespace as exc:
                return _namespace_problem(request, exc)
        return Response(
            content=body,
            media_type=media_type,
            headers={
                "Content-Disposition": f'attachment; filename="{filename}"',
                **NO_STORE,
            },
        )

    @router.post("/i18n/import")
    def import_catalog(
        request: Request,
        payload: ImportRequest,
        context: MutationDependency,
    ) -> JSONResponse:
        """Validate and store a catalog in the locale's custom layer (D5: highest)."""
        locale = resolve_request_locale(request)
        with request.app.state.session_factory() as session:
            identity = _service_for(request, session)
            identity.authorize(context.principal, "system.configure", resource="i18n:custom:import")
            snapshot = registry.snapshot(session)
            canonical = snapshot.resolve(payload.locale)
            if canonical is None:
                return _not_found(request, "api.i18n.unknown_locale", locale=payload.locale)
            try:
                report = tools.catalog_report(
                    session,
                    canonical,
                    payload.format,
                    payload.content,
                    sources=tools.source_texts(session),
                    dry_run=payload.dryRun,
                )
            except tools.UnsupportedFormat as exc:
                return _format_problem(request, exc)
            if report["valid"] and report["applied"]:
                identity.record_operation(
                    context.principal,
                    action="i18n.custom_imported",
                    resource=f"i18n:custom:{canonical}",
                    commit=False,
                )
            if report["valid"]:
                session.commit()
                report["revision"] = registry.revision(session)
                return JSONResponse(content=report, headers=NO_STORE)
            params = {"count": len(report["problems"])}
            body = error_payload(
                "validation_error",
                t("api.i18n.import_invalid", locale, **params),
                key="api.i18n.import_invalid",
                params=params,
            )
            body["report"] = report
            return JSONResponse(status_code=422, content=body, headers=NO_STORE)

    @router.post("/i18n/validate")
    def validate_catalog(
        request: Request,
        payload: CatalogRequest,
        context: AuthDependency,
    ) -> JSONResponse:
        """Return the import report of a posted catalog without writing anything."""
        with request.app.state.session_factory() as session:
            identity = _service_for(request, session)
            identity.authorize(context.principal, "system.view", resource="i18n:validate")
            snapshot = registry.snapshot(session)
            canonical = snapshot.resolve(payload.locale)
            if canonical is None:
                return _not_found(request, "api.i18n.unknown_locale", locale=payload.locale)
            try:
                report = tools.catalog_report(
                    session,
                    canonical,
                    payload.format,
                    payload.content,
                    sources=tools.source_texts(session),
                    dry_run=True,
                )
            except tools.UnsupportedFormat as exc:
                return _format_problem(request, exc)
        return JSONResponse(content=report, headers=NO_STORE)

    @router.delete("/i18n/custom/{locale}")
    def reset_custom_layer(
        request: Request,
        locale: str,
        context: MutationDependency,
    ) -> JSONResponse:
        """Drop every custom translation of one locale and bump the revision."""
        return _delete_custom(request, context, locale, None)

    @router.delete("/i18n/custom/{locale}/{key}")
    def delete_custom_translation(
        request: Request,
        locale: str,
        key: str,
        context: MutationDependency,
    ) -> JSONResponse:
        """Drop one custom translation of one locale and bump the revision."""
        return _delete_custom(request, context, locale, key)

    return router


def _delete_custom(
    request: Request,
    context: MutationDependency,
    locale: str,
    key: str | None,
) -> JSONResponse:
    """Shared delete path: authorize, resolve, delete, audit and commit once."""
    with request.app.state.session_factory() as session:
        identity = _service_for(request, session)
        identity.authorize(context.principal, "system.configure", resource="i18n:custom:delete")
        snapshot = registry.snapshot(session)
        canonical = snapshot.resolve(locale)
        if canonical is None:
            return _not_found(request, "api.i18n.unknown_locale", locale=locale)
        deleted = registry.delete_custom_translations(
            session, canonical, None if key is None else [key]
        )
        if key is not None and deleted == 0:
            return _not_found(request, "api.i18n.custom_key_not_found", locale=canonical, key=key)
        if deleted:
            identity.record_operation(
                context.principal,
                action="i18n.custom_deleted",
                resource=f"i18n:custom:{canonical}",
                commit=False,
            )
        session.commit()
        revision = registry.revision(session)
    return JSONResponse(
        content={"locale": canonical, "deleted": deleted, "revision": revision},
        headers=NO_STORE,
    )
