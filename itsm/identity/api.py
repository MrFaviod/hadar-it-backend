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

from itsm.demo.state import is_demo
from itsm.identity.service import (
    AccountThrottled,
    AuditView,
    AuthContext,
    AuthenticationFailed,
    BootstrapRefused,
    Conflict,
    CurrentView,
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


def error_body(code: str, message: str) -> dict[str, dict[str, str]]:
    return {"error": {"code": code, "message": message}}


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


class SessionEnvelope(BaseModel):
    user: UserDTO
    permissions: list[str]
    csrfToken: str | None
    sessionMinutes: int
    # Additive, server-derived installation identity. Legacy payloads that omit
    # it stay ordinary installations; a client can never set it.
    demoMode: bool = False


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


def session_envelope(view: CurrentView, *, demo_mode: bool = False) -> SessionEnvelope:
    return SessionEnvelope(
        user=user_dto(view.user),
        permissions=sorted(view.permissions),
        csrfToken=view.csrf_token,
        sessionMinutes=view.session_minutes,
        demoMode=demo_mode,
    )


def audit_dto(event: AuditView) -> AuditEventDTO:
    return AuditEventDTO(**audit_event_payload(event))


# ---------------------------------------------------------------- dependencies
def get_identity_service(request: Request) -> Iterator[IdentityService]:
    factory = request.app.state.session_factory
    session = factory()
    try:
        yield IdentityService(session, request.app.state.settings)
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
        raise PermissionDenied("request origin is not allowed")


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
        raise PermissionDenied("csrf token is invalid")
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
        body = session_envelope(service.me(grant), demo_mode=demo_mode)
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
        body = session_envelope(service.me(context), demo_mode=demo_mode)
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
    """Translate identity domain errors into the shared error envelope."""

    def json_error(
        status_code: int, code: str, message: str, headers: dict[str, str] | None = None
    ) -> JSONResponse:
        return JSONResponse(
            status_code=status_code, content=error_body(code, message), headers=headers
        )

    @app.exception_handler(ValidationFailed)
    async def on_validation(request: Request, exc: ValidationFailed) -> JSONResponse:
        return json_error(422, "validation_error", str(exc))

    @app.exception_handler(NotFound)
    async def on_not_found(request: Request, exc: NotFound) -> JSONResponse:
        return json_error(404, "not_found", str(exc))

    @app.exception_handler(Conflict)
    async def on_conflict(request: Request, exc: Conflict) -> JSONResponse:
        return json_error(409, "conflict", str(exc))

    @app.exception_handler(BootstrapRefused)
    async def on_bootstrap_refused(request: Request, exc: BootstrapRefused) -> JSONResponse:
        return json_error(409, "conflict", str(exc))

    @app.exception_handler(PermissionDenied)
    async def on_permission_denied(request: Request, exc: PermissionDenied) -> JSONResponse:
        return json_error(403, "forbidden", str(exc))

    @app.exception_handler(AuthenticationFailed)
    async def on_authentication_failed(request: Request, exc: AuthenticationFailed) -> JSONResponse:
        return json_error(401, "unauthorized", str(exc))

    @app.exception_handler(AccountThrottled)
    async def on_throttled(request: Request, exc: AccountThrottled) -> JSONResponse:
        return json_error(
            429,
            "too_many_requests",
            str(exc),
            headers={"Retry-After": str(exc.retry_after_seconds)},
        )

    @app.exception_handler(AuthenticationRequired)
    async def on_authentication_required(
        request: Request, exc: AuthenticationRequired
    ) -> JSONResponse:
        response = json_error(401, "unauthorized", "authentication required")
        clear_session_cookie(request, response)
        return response
