"""FastAPI router and error handlers for the identity module.

JSON field names are camelCase here because they are the public contract used
by the existing UI; the domain service keeps snake_case names.
"""

from __future__ import annotations

import secrets
from collections.abc import Iterator
from typing import Annotated

from fastapi import APIRouter, Depends, FastAPI, Query, Request, Response, status
from fastapi.responses import JSONResponse
from pydantic import BaseModel, ConfigDict, Field

from itsm.demo.restrictions import DEMO_HIDDEN_PERMISSIONS, visitor_password_waiver
from itsm.demo.state import is_demo
from itsm.i18n.envelope import error_payload
from itsm.i18n.messages import t
from itsm.i18n.request import resolve_request_locale
from itsm.i18n.settings import InstallationSettings
from itsm.identity.service import (
    AccountThrottled,
    AuditView,
    AuthContext,
    AuthenticationFailed,
    BootstrapRefused,
    Conflict,
    CurrentView,
    IdentityError,
    IdentityService,
    NotFound,
    PermissionDenied,
    RoleView,
    UserView,
    ValidationFailed,
    audit_event_payload,
)

COOKIE_PATH = "/"
CSRF_HEADER = "X-CSRF-Token"
ORIGIN_HEADER = "Origin"
MUTATION_METHODS = frozenset({"POST", "PUT", "PATCH", "DELETE"})
NO_STORE = {"Cache-Control": "no-store"}


class AuthenticationRequired(Exception):
    """Raised when a request has no usable session or machine credential."""

    key = "api.auth.authentication_required"


def error_body(
    code: str,
    message: str,
    *,
    key: str | None = None,
    params: dict[str, object] | None = None,
) -> dict[str, object]:
    """The shared envelope; ``key``/``params`` are additive when localized."""
    return error_payload(code, message, key=key, params=params)


# ------------------------------------------------------------------ envelopes
class UserDTO(BaseModel):
    id: str
    username: str
    name: str
    email: str | None
    roleId: str | None
    active: bool
    lastAccess: str | None
    personId: str | None
    actorKind: str


class RoleDTO(BaseModel):
    id: str
    name: str
    permissions: list[str]
    builtIn: bool


class PreferencesDTO(BaseModel):
    locale: str | None


class InstallationDTO(BaseModel):
    defaultLocale: str
    timezone: str
    currency: str


class SessionEnvelope(BaseModel):
    user: UserDTO
    permissions: list[str]
    csrfToken: str | None
    sessionMinutes: int
    # Additive, server-derived installation identity. Legacy payloads that omit
    # it stay ordinary installations; a client can never set it.
    demoMode: bool = False
    # Additive i18n contract (D11): effective locale, the caller's own
    # preference (``None`` follows the installation) and the installation
    # defaults every client must format numbers and dates with.
    locale: str
    preferences: PreferencesDTO
    installation: InstallationDTO


class StateDTO(BaseModel):
    users: list[UserDTO]
    roles: list[RoleDTO]
    sessionMinutes: int


class CatalogDTO(BaseModel):
    permissions: list[str]
    actorKinds: list[str]


class AuditEventDTO(BaseModel):
    actorId: str | None
    actorKind: str
    actorUsername: str | None
    action: str
    resource: str
    outcome: str
    createdAt: str
    executionId: str | None
    delegatedBy: str | None
    authorizationRef: str | None


class AuditDTO(BaseModel):
    events: list[AuditEventDTO]


class SettingsDTO(BaseModel):
    sessionMinutes: int


class LoginRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    username: str = Field(min_length=1, max_length=128)
    password: str = Field(min_length=1, max_length=1024)


class UserCreateRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    username: str = Field(min_length=3, max_length=64)
    name: str = Field(min_length=1, max_length=120)
    roleId: str = Field(min_length=1, max_length=64)
    email: str | None = Field(default=None, max_length=254)
    personId: str | None = Field(default=None, max_length=64)
    actorKind: str = Field(default="human", max_length=32)
    active: bool = True
    password: str | None = Field(default=None, max_length=1024)
    delegatedById: str | None = Field(default=None, max_length=36)


class UserUpdateRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    username: str | None = Field(default=None, min_length=3, max_length=64)
    name: str | None = Field(default=None, min_length=1, max_length=120)
    email: str | None = Field(default=None, max_length=254)
    roleId: str | None = Field(default=None, max_length=64)
    personId: str | None = Field(default=None, max_length=64)
    actorKind: str | None = Field(default=None, max_length=32)
    active: bool | None = None
    password: str | None = Field(default=None, max_length=1024)
    delegatedById: str | None = Field(default=None, max_length=36)


class ActiveRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    active: bool


class RoleCreateRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    name: str = Field(min_length=1, max_length=120)
    permissions: list[str] = Field(default_factory=list, max_length=128)


class RoleUpdateRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    name: str | None = Field(default=None, min_length=1, max_length=120)
    permissions: list[str] | None = Field(default=None, max_length=128)


class SettingsRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    sessionMinutes: int


class PreferencesRequest(BaseModel):
    """Only the caller's own locale; ``null`` follows the installation."""

    model_config = ConfigDict(extra="forbid")

    locale: str | None = Field(default=None, max_length=35)


def user_dto(view: UserView) -> UserDTO:
    return UserDTO(
        id=view.id,
        username=view.username,
        name=view.name,
        email=view.email,
        roleId=view.role_id,
        active=view.active,
        lastAccess=view.last_access.isoformat() if view.last_access else None,
        personId=view.person_id,
        actorKind=view.actor_kind,
    )


def role_dto(view: RoleView) -> RoleDTO:
    return RoleDTO(
        id=view.id,
        name=view.name,
        permissions=list(view.permissions),
        builtIn=view.built_in,
    )


def session_envelope(
    view: CurrentView,
    *,
    installation: InstallationSettings,
    demo_mode: bool = False,
) -> SessionEnvelope:
    return SessionEnvelope(
        user=user_dto(view.user),
        permissions=sorted(
            view.permissions - DEMO_HIDDEN_PERMISSIONS if demo_mode else view.permissions
        ),
        csrfToken=view.csrf_token,
        sessionMinutes=view.session_minutes,
        demoMode=demo_mode,
        locale=view.user.locale or installation.default_locale,
        preferences=PreferencesDTO(locale=view.user.locale),
        installation=InstallationDTO(
            defaultLocale=installation.default_locale,
            timezone=installation.timezone,
            currency=installation.currency,
        ),
    )


def audit_dto(event: AuditView) -> AuditEventDTO:
    return AuditEventDTO(**audit_event_payload(event))


# ---------------------------------------------------------------- dependencies
def get_identity_service(request: Request) -> Iterator[IdentityService]:
    state = request.app.state
    factory = state.session_factory
    session = factory()
    # The demo policy travels with the release capabilities resolved at startup,
    # so every request-scoped service validates passwords and bounds sessions the
    # same way the guard does. ``prod`` and ``dev`` pass ``None`` for both.
    capabilities = getattr(state, "release_capabilities", None)
    limits = getattr(state, "demo_limits", None)
    try:
        yield IdentityService(
            session,
            state.settings,
            session_cap=None if limits is None else limits.session_cap,
            password_waiver=None if capabilities is None else visitor_password_waiver(capabilities),
        )
    finally:
        session.close()


def _bearer_token(request: Request) -> str | None:
    header = request.headers.get("authorization", "")
    if not header.lower().startswith("bearer "):
        return None
    return header[7:].strip() or None


def authenticated_actor(
    request: Request,
    service: Annotated[IdentityService, Depends(get_identity_service)],
) -> AuthContext:
    """Resolve a cookie session or a machine bearer credential."""
    token = _bearer_token(request)
    try:
        if token is not None:
            return service.authenticate_token(
                token,
                execution_id=request.headers.get("x-execution-id"),
                authorization_ref=request.headers.get("x-authorization-ref"),
            )
        cookie_name = request.app.state.settings.auth_cookie_name
        return service.authenticate_session(request.cookies.get(cookie_name))
    except AuthenticationFailed as exc:
        raise AuthenticationRequired() from exc


def _origin_allowed(request: Request) -> bool:
    return request.headers.get(ORIGIN_HEADER) == request.app.state.settings.auth_origin


def _require_origin(request: Request) -> None:
    if not _origin_allowed(request):
        raise PermissionDenied("request origin is not allowed", key="api.auth.origin_not_allowed")


def mutation_guard(
    request: Request,
    context: Annotated[AuthContext, Depends(authenticated_actor)],
) -> AuthContext:
    """Origin plus CSRF for cookie sessions; bearer machine calls are exempt."""
    if context.csrf_token is None:
        return context
    _require_origin(request)
    supplied = request.headers.get(CSRF_HEADER, "")
    if not supplied or not secrets.compare_digest(supplied, context.csrf_token):
        raise PermissionDenied("csrf token is invalid", key="api.auth.csrf_invalid")
    return context


def read_demo_mode(request: Request) -> bool:
    """Read the durable demo marker through the application session seam.

    This reports persisted installation identity only; it grants nothing and no
    request input reaches it. Migrations are an explicit prerequisite, so a
    failed read is surfaced instead of being reported as an ordinary
    installation; guessing here would misstate the installation's identity.
    """
    session = request.app.state.session_factory()
    try:
        return is_demo(session)
    finally:
        session.close()


AuthDependency = Annotated[AuthContext, Depends(authenticated_actor)]
MutationDependency = Annotated[AuthContext, Depends(mutation_guard)]
ServiceDependency = Annotated[IdentityService, Depends(get_identity_service)]
DemoModeDependency = Annotated[bool, Depends(read_demo_mode)]


def _cookie_secure(request: Request) -> bool:
    return bool(request.app.state.settings.auth_cookie_secure)


def set_session_cookie(request: Request, response: Response, token: str, minutes: int) -> None:
    response.set_cookie(
        key=request.app.state.settings.auth_cookie_name,
        value=token,
        max_age=minutes * 60,
        path=COOKIE_PATH,
        httponly=True,
        secure=_cookie_secure(request),
        samesite="strict",
    )


def clear_session_cookie(request: Request, response: Response) -> None:
    response.delete_cookie(
        key=request.app.state.settings.auth_cookie_name,
        path=COOKIE_PATH,
        httponly=True,
        secure=_cookie_secure(request),
        samesite="strict",
    )


# ---------------------------------------------------------------------- routes
def create_identity_router() -> APIRouter:
    router = APIRouter()

    @router.post("/auth/login")
    def login(
        payload: LoginRequest,
        request: Request,
        service: ServiceDependency,
        demo_mode: DemoModeDependency,
    ) -> JSONResponse:
        _require_origin(request)
        grant = service.login(payload.username, payload.password)
        body = session_envelope(
            service.me(grant),
            installation=service.installation_settings(),
            demo_mode=demo_mode,
        )
        response = JSONResponse(content=body.model_dump(mode="json"), headers=NO_STORE)
        set_session_cookie(request, response, grant.token, grant.session_minutes)
        return response

    @router.get("/auth/me")
    def me(
        request: Request,
        context: AuthDependency,
        service: ServiceDependency,
        demo_mode: DemoModeDependency,
    ) -> JSONResponse:
        body = session_envelope(
            service.me(context),
            installation=service.installation_settings(),
            demo_mode=demo_mode,
        )
        return JSONResponse(content=body.model_dump(mode="json"), headers=NO_STORE)

    @router.patch("/auth/me/preferences")
    def update_preferences(
        payload: PreferencesRequest,
        context: MutationDependency,
        service: ServiceDependency,
        demo_mode: DemoModeDependency,
    ) -> JSONResponse:
        """Only the caller's own locale changes; the session envelope comes back."""
        service.update_preferences(context.principal, locale=payload.locale)
        body = session_envelope(
            service.me(context),
            installation=service.installation_settings(),
            demo_mode=demo_mode,
        )
        return JSONResponse(content=body.model_dump(mode="json"), headers=NO_STORE)

    @router.post("/auth/logout")
    def logout(
        request: Request,
        context: MutationDependency,
        service: ServiceDependency,
    ) -> JSONResponse:
        service.logout(context.principal)
        response = JSONResponse(content={"status": "ok"}, headers=NO_STORE)
        clear_session_cookie(request, response)
        return response

    @router.get("/identity/state")
    def state(context: AuthDependency, service: ServiceDependency) -> StateDTO:
        view = service.state(context)
        return StateDTO(
            users=[user_dto(user) for user in view.users],
            roles=[role_dto(role) for role in view.roles],
            sessionMinutes=view.session_minutes,
        )

    @router.get("/identity/catalog")
    def catalog(context: AuthDependency, service: ServiceDependency) -> CatalogDTO:
        view = service.catalog(context.principal)
        return CatalogDTO(
            permissions=list(view.permissions),
            actorKinds=list(view.actor_kinds),
        )

    @router.get("/identity/audit")
    def audit(
        context: AuthDependency,
        service: ServiceDependency,
        limit: Annotated[int, Query(ge=1, le=200)] = 50,
    ) -> AuditDTO:
        events = service.list_audit(context.principal, limit=limit)
        return AuditDTO(events=[audit_dto(event) for event in events])

    @router.post("/identity/users", status_code=status.HTTP_201_CREATED)
    def create_user(
        payload: UserCreateRequest,
        context: MutationDependency,
        service: ServiceDependency,
    ) -> UserDTO:
        view = service.create_user(
            context.principal,
            username=payload.username,
            name=payload.name,
            role_id=payload.roleId,
            email=payload.email,
            person_id=payload.personId,
            actor_kind=payload.actorKind,
            active=payload.active,
            password=payload.password,
            delegated_by_id=payload.delegatedById,
        )
        return user_dto(view)

    @router.put("/identity/users/{identity_id}")
    def update_user(
        identity_id: str,
        payload: UserUpdateRequest,
        context: MutationDependency,
        service: ServiceDependency,
    ) -> UserDTO:
        view = service.update_user(
            context.principal,
            identity_id,
            username=payload.username,
            name=payload.name,
            email=payload.email,
            role_id=payload.roleId,
            person_id=payload.personId,
            actor_kind=payload.actorKind,
            active=payload.active,
            password=payload.password,
            delegated_by_id=payload.delegatedById,
        )
        return user_dto(view)

    @router.patch("/identity/users/{identity_id}/active")
    def set_active(
        identity_id: str,
        payload: ActiveRequest,
        context: MutationDependency,
        service: ServiceDependency,
    ) -> UserDTO:
        view = service.set_active(context.principal, identity_id, active=payload.active)
        return user_dto(view)

    @router.post("/identity/roles", status_code=status.HTTP_201_CREATED)
    def create_role(
        payload: RoleCreateRequest,
        context: MutationDependency,
        service: ServiceDependency,
    ) -> RoleDTO:
        view = service.create_role(
            context.principal, name=payload.name, permissions=payload.permissions
        )
        return role_dto(view)

    @router.put("/identity/roles/{role_id}")
    def update_role(
        role_id: str,
        payload: RoleUpdateRequest,
        context: MutationDependency,
        service: ServiceDependency,
    ) -> RoleDTO:
        view = service.update_role(
            context.principal,
            role_id,
            name=payload.name,
            permissions=payload.permissions,
        )
        return role_dto(view)

    @router.put("/identity/settings")
    def update_settings(
        payload: SettingsRequest,
        context: MutationDependency,
        service: ServiceDependency,
    ) -> SettingsDTO:
        minutes = service.update_settings(context.principal, session_minutes=payload.sessionMinutes)
        return SettingsDTO(sessionMinutes=minutes)

    return router


def install_error_handlers(app: FastAPI) -> None:
    """Translate identity domain errors into the shared, localized envelope."""

    def json_error(
        request: Request,
        status_code: int,
        code: str,
        message: str,
        *,
        key: str | None = None,
        params: dict[str, object] | None = None,
        headers: dict[str, str] | None = None,
    ) -> JSONResponse:
        return JSONResponse(
            status_code=status_code,
            content=error_body(code, message, key=key, params=params),
            headers=headers,
        )

    def localized(
        request: Request, code: str, message: str, exc: IdentityError
    ) -> tuple[str, str | None, dict[str, object] | None]:
        """Localize only when the domain error carries a stable key."""
        if exc.key is None:
            return message, None, None
        return t(exc.key, resolve_request_locale(request), **exc.params), exc.key, exc.params

    @app.exception_handler(ValidationFailed)
    async def on_validation(request: Request, exc: ValidationFailed) -> JSONResponse:
        message, key, params = localized(request, "validation_error", str(exc), exc)
        return json_error(request, 422, "validation_error", message, key=key, params=params)

    @app.exception_handler(NotFound)
    async def on_not_found(request: Request, exc: NotFound) -> JSONResponse:
        message, key, params = localized(request, "not_found", str(exc), exc)
        return json_error(request, 404, "not_found", message, key=key, params=params)

    @app.exception_handler(Conflict)
    async def on_conflict(request: Request, exc: Conflict) -> JSONResponse:
        message, key, params = localized(request, "conflict", str(exc), exc)
        return json_error(request, 409, "conflict", message, key=key, params=params)

    @app.exception_handler(BootstrapRefused)
    async def on_bootstrap_refused(request: Request, exc: BootstrapRefused) -> JSONResponse:
        message, key, params = localized(request, "conflict", str(exc), exc)
        return json_error(request, 409, "conflict", message, key=key, params=params)

    @app.exception_handler(PermissionDenied)
    async def on_permission_denied(request: Request, exc: PermissionDenied) -> JSONResponse:
        message, key, params = localized(request, "forbidden", str(exc), exc)
        return json_error(request, 403, "forbidden", message, key=key, params=params)

    @app.exception_handler(AuthenticationFailed)
    async def on_authentication_failed(request: Request, exc: AuthenticationFailed) -> JSONResponse:
        message, key, params = localized(request, "unauthorized", str(exc), exc)
        return json_error(request, 401, "unauthorized", message, key=key, params=params)

    @app.exception_handler(AccountThrottled)
    async def on_throttled(request: Request, exc: AccountThrottled) -> JSONResponse:
        message, key, params = localized(request, "too_many_requests", str(exc), exc)
        return json_error(
            request,
            429,
            "too_many_requests",
            message,
            key=key,
            params=params,
            headers={"Retry-After": str(exc.retry_after_seconds)},
        )

    @app.exception_handler(AuthenticationRequired)
    async def on_authentication_required(
        request: Request, exc: AuthenticationRequired
    ) -> JSONResponse:
        key = exc.key
        response = json_error(
            request,
            401,
            "unauthorized",
            t(key, resolve_request_locale(request)),
            key=key,
            params={},
        )
        # A rejected machine credential says nothing about the browser session; only
        # a request that relied on the cookie may have that cookie cleared.
        if "authorization" not in request.headers:
            clear_session_cookie(request, response)
        return response
