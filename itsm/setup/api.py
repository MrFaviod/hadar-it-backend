"""FastAPI application for setup and onboarding without a database.

The app is mounted at ``/api/setup/v1`` and is built by
:func:`create_setup_app`. It reads only the private bootstrap store; importing
this module must not import :mod:`itsm.main`, create an engine or open a
database connection. Anonymous callers can read the sanitized status. Claim
and every session mutation are origin-checked; session mutations additionally
require the ``X-CSRF-Token`` value returned once by the claim response.
"""

from __future__ import annotations

import secrets
from collections.abc import Callable, Mapping
from datetime import datetime
from pathlib import Path
from typing import Any

from fastapi import APIRouter, Depends, FastAPI, Request, Response
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse

from itsm import __version__
from itsm.setup.schemas import (
    ClaimRequest,
    ClaimResponse,
    SanitizedStatus,
    SessionResponse,
)
from itsm.setup.store import (
    SESSION_TTL_MINUTES,
    AlreadyClaimed,
    ClaimLocked,
    ClaimUnavailable,
    InvalidCredential,
    NotClaimed,
    RevisionConflict,
    SetupConfigurationError,
    SetupDisabled,
    SetupError,
    SetupSettings,
    SetupStore,
    StoreUnsafe,
)

SETUP_PREFIX = "/api/setup/v1"
COOKIE_NAME = "itsm_setup_session"
ORIGIN_HEADER = "Origin"
CSRF_HEADER = "X-CSRF-Token"
NO_STORE = {"Cache-Control": "no-store"}


class ApiError(Exception):
    """A sanitized HTTP refusal raised from a route or dependency."""

    def __init__(self, status_code: int, code: str) -> None:
        super().__init__(code)
        self.status_code = status_code
        self.code = code


_ERROR_STATUS: tuple[tuple[type[SetupError], int], ...] = (
    (SetupDisabled, 403),
    (AlreadyClaimed, 409),
    (NotClaimed, 409),
    (ClaimLocked, 429),
    (InvalidCredential, 401),
    (ClaimUnavailable, 403),
    (RevisionConflict, 409),
    (StoreUnsafe, 503),
    (SetupConfigurationError, 503),
)


def _error_response(status_code: int, code: str) -> JSONResponse:
    return JSONResponse({"error": code}, status_code=status_code, headers=NO_STORE)


def _setup_error_response(exc: SetupError) -> JSONResponse:
    for error_type, status_code in _ERROR_STATUS:
        if isinstance(exc, error_type):
            return _error_response(status_code, exc.code)
    return _error_response(500, "setup_error")


def require_origin(request: Request) -> None:
    """Reject a non-GET request whose ``Origin`` is not explicitly allowed."""

    origin = request.headers.get(ORIGIN_HEADER)
    if not origin:
        raise ApiError(403, "origin_not_allowed")
    settings: SetupSettings = request.app.state.setup_settings
    if settings.allowed_origins:
        allowed = origin in settings.allowed_origins
    else:
        allowed = origin == str(request.base_url).rstrip("/")
    if not allowed:
        raise ApiError(403, "origin_not_allowed")


def get_store(request: Request) -> SetupStore:
    return request.app.state.setup_store


def current_session(request: Request) -> dict[str, Any]:
    """Resolve the server-side setup session from its HttpOnly cookie."""

    token = request.cookies.get(COOKIE_NAME)
    record = get_store(request).resolve_session(token) if token else None
    if record is None:
        raise ApiError(401, "authentication_required")
    return record


def require_session_mutation(
    request: Request,
    session: dict[str, Any] = Depends(current_session),
) -> dict[str, Any]:
    """Guard a session mutation with Origin and a constant-time CSRF check."""

    require_origin(request)
    supplied = request.headers.get(CSRF_HEADER, "")
    expected = str(session.get("csrf_token", ""))
    if not supplied or not expected or not secrets.compare_digest(supplied, expected):
        raise ApiError(403, "csrf_invalid")
    return session


def _set_session_cookie(response: Response, token: str, settings: SetupSettings) -> None:
    response.set_cookie(
        key=COOKIE_NAME,
        value=token,
        max_age=SESSION_TTL_MINUTES * 60,
        path=SETUP_PREFIX,
        httponly=True,
        secure=settings.cookie_secure,
        samesite="strict",
    )


def _clear_session_cookie(response: Response, settings: SetupSettings) -> None:
    response.delete_cookie(
        key=COOKIE_NAME,
        path=SETUP_PREFIX,
        httponly=True,
        secure=settings.cookie_secure,
        samesite="strict",
    )


def create_setup_router() -> APIRouter:
    router = APIRouter(prefix=SETUP_PREFIX)

    @router.get("/status")
    def status(request: Request) -> JSONResponse:
        settings: SetupSettings = request.app.state.setup_settings
        snapshot = get_store(request).status_snapshot()
        payload = SanitizedStatus(
            state=snapshot["state"],
            mode=settings.release_mode,
            release_mode=settings.release_mode,
            setup_enabled=snapshot["setup_enabled"],
            claim_available=snapshot["claim_available"],
            backend="unknown",
            version=__version__,
            instance_id=snapshot["instance_id"],
        )
        return JSONResponse(payload.model_dump(mode="json"), headers=NO_STORE)

    @router.post("/claim")
    def claim(payload: ClaimRequest, request: Request) -> JSONResponse:
        require_origin(request)
        settings: SetupSettings = request.app.state.setup_settings
        grant = get_store(request).claim(payload.credential.get_secret_value())
        body = ClaimResponse(
            state=grant.state,
            mode=settings.release_mode,
            release_mode=settings.release_mode,
            csrf_token=grant.csrf_token,
        )
        response = JSONResponse(body.model_dump(mode="json"), headers=NO_STORE)
        _set_session_cookie(response, grant.token, settings)
        return response

    @router.get("/session")
    def session(request: Request) -> JSONResponse:
        settings: SetupSettings = request.app.state.setup_settings
        store = get_store(request)
        token = request.cookies.get(COOKIE_NAME)
        record = store.resolve_session(token)
        if record is None:
            response = _error_response(401, "authentication_required")
            if token:
                _clear_session_cookie(response, settings)
            return response
        snapshot = store.status_snapshot()
        body = SessionResponse(
            state=snapshot["state"],
            mode=settings.release_mode,
            release_mode=settings.release_mode,
            checks=[],
        )
        return JSONResponse(body.model_dump(mode="json"), headers=NO_STORE)

    return router


def create_setup_app(
    *,
    state_dir: str | Path | None = None,
    clock: Callable[[], datetime] | None = None,
    environ: Mapping[str, str] | None = None,
    settings: SetupSettings | None = None,
) -> FastAPI:
    """Build the setup app for one private state directory and clock."""

    resolved = settings or SetupSettings.from_environ(environ)
    if state_dir is not None:
        resolved = resolved.with_state_dir(state_dir)
    store = SetupStore(
        resolved.state_dir,
        clock=clock,
        release_mode=resolved.release_mode,
    )
    store.validate()

    app = FastAPI(
        title="ITSM setup",
        version=__version__,
        docs_url=None,
        redoc_url=None,
        openapi_url=None,
    )
    app.state.setup_settings = resolved
    app.state.setup_store = store
    app.include_router(create_setup_router())

    @app.exception_handler(ApiError)
    def api_error_handler(request: Request, exc: ApiError) -> JSONResponse:
        return _error_response(exc.status_code, exc.code)

    @app.exception_handler(SetupError)
    def setup_error_handler(request: Request, exc: SetupError) -> JSONResponse:
        return _setup_error_response(exc)

    @app.exception_handler(RequestValidationError)
    def validation_error_handler(request: Request, exc: RequestValidationError) -> JSONResponse:
        return _error_response(422, "invalid_request")

    return app
