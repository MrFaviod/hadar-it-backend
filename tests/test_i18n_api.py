"""i18n HTTP contract: public catalogs, preferences and localized envelopes."""

from __future__ import annotations

import os
from collections.abc import Callable, Iterator

import pytest
from fastapi.testclient import TestClient
from itsm.config import Settings
from itsm.database import create_engine_from_settings
from itsm.demo.state import DemoInstallation
from itsm.identity.clock import utcnow
from itsm.main import create_app
from itsm.release_mode import RELEASE_MODE_ENV
from sqlalchemy.orm import Session
from tests.conftest import run_migrations
from tests.identity_support import Harness

ORIGIN = "http://testserver"
API = "/api/v1"
ADMIN_PASSWORD = "installer-password-2026"
SECOND_PASSWORD = "second-admin-password-2026"


@pytest.fixture
def env(settings_factory: Callable[..., Settings]) -> Iterator[tuple[TestClient, Harness]]:
    settings = settings_factory()
    applied = run_migrations(settings)
    assert applied.returncode == 0, applied.stderr
    harness = Harness(settings=settings, engine=create_engine_from_settings(settings))
    with harness.service() as service:
        service.bootstrap_superadmin("ana.admin", "Ana Admin", ADMIN_PASSWORD)
    with TestClient(create_app(settings)) as client:
        try:
            yield client, harness
        finally:
            harness.close()


def login(
    client: TestClient,
    username: str = "ana.admin",
    password: str = ADMIN_PASSWORD,
    *,
    headers: dict[str, str] | None = None,
):
    return client.post(
        f"{API}/auth/login",
        json={"username": username, "password": password},
        headers={"Origin": ORIGIN, **(headers or {})},
    )


def auth_headers(client: TestClient, username: str = "ana.admin", password: str = ADMIN_PASSWORD):
    response = login(client, username, password)
    assert response.status_code == 200, response.text
    return {"Origin": ORIGIN, "X-CSRF-Token": str(response.json()["csrfToken"])}


def test_locales_endpoint_is_public_and_reports_the_core_catalogs(env) -> None:
    client, _ = env

    response = client.get(f"{API}/i18n/locales")

    assert response.status_code == 200, response.text
    payload = response.json()
    assert payload["revision"] == 0
    assert payload["defaultLocale"] == "es"
    assert payload["formats"] == {"timezone": "America/Asuncion", "currency": "PYG"}
    assert {entry["tag"] for entry in payload["locales"]} == {"es", "en"}
    spanish = next(entry for entry in payload["locales"] if entry["tag"] == "es")
    assert spanish == {
        "tag": "es",
        "name": "Spanish",
        "nativeName": "Español",
        "provider": "core",
    }


def test_bundle_serves_both_locales_with_etag_revalidation(env) -> None:
    client, _ = env

    spanish = client.get(f"{API}/i18n/bundle", params={"locale": "es"})
    assert spanish.status_code == 200, spanish.text
    body = spanish.json()
    assert body["locale"] == "es"
    assert body["revision"] == 0
    assert body["fallback"] == ["es"]
    assert body["overrides"] == {}
    assert body["messages"]["api.error.not_found"] == "No encontrado."
    etag = spanish.headers["etag"]
    assert etag

    revalidated = client.get(
        f"{API}/i18n/bundle",
        params={"locale": "es"},
        headers={"If-None-Match": etag},
    )
    assert revalidated.status_code == 304
    assert revalidated.content == b""
    assert revalidated.headers["etag"] == etag

    english = client.get(f"{API}/i18n/bundle", params={"locale": "en"})
    assert english.status_code == 200, english.text
    assert english.json()["messages"]["api.error.not_found"] == "Not found."
    assert english.headers["etag"] != etag


def test_bundle_rejects_an_unknown_locale(env) -> None:
    client, _ = env

    response = client.get(
        f"{API}/i18n/bundle",
        params={"locale": "xx"},
        headers={"Accept-Language": "es"},
    )

    assert response.status_code == 404, response.text
    error = response.json()["error"]
    assert error["code"] == "not_found"
    assert error["key"] == "api.i18n.unknown_locale"
    assert error["params"] == {"locale": "xx"}
    assert error["message"] == "El idioma xx no está instalado."


def test_user_preference_persists_across_sessions_and_is_per_user(env) -> None:
    client, _ = env
    headers = auth_headers(client)

    updated = client.patch(
        f"{API}/auth/me/preferences",
        json={"locale": "en"},
        headers=headers,
    )
    assert updated.status_code == 200, updated.text
    assert updated.json()["locale"] == "en"
    assert updated.json()["preferences"] == {"locale": "en"}

    assert client.post(f"{API}/auth/logout", headers=headers).status_code == 200
    relogged = login(client)
    assert relogged.status_code == 200, relogged.text
    assert relogged.json()["locale"] == "en"
    assert relogged.json()["preferences"] == {"locale": "en"}
    headers = auth_headers(client)

    created = client.post(
        f"{API}/identity/users",
        json={
            "username": "bea.admin",
            "name": "Bea Admin",
            "roleId": "admin",
            "password": SECOND_PASSWORD,
        },
        headers=headers,
    )
    assert created.status_code == 201, created.text

    assert client.post(f"{API}/auth/logout", headers=headers).status_code == 200
    response = login(client, "bea.admin", SECOND_PASSWORD)
    assert response.status_code == 200, response.text
    assert response.json()["locale"] == "es"
    assert response.json()["preferences"] == {"locale": None}


def test_anonymous_accept_language_selects_the_error_locale(env) -> None:
    client, _ = env

    spanish = client.get(f"{API}/auth/me")
    assert spanish.status_code == 401
    assert spanish.json()["error"]["key"] == "api.auth.authentication_required"
    assert spanish.json()["error"]["message"] == "Se requiere autenticación."

    english = client.get(f"{API}/auth/me", headers={"Accept-Language": "en-US,en;q=0.9"})
    assert english.status_code == 401
    assert english.json()["error"]["key"] == "api.auth.authentication_required"
    assert english.json()["error"]["message"] == "Authentication required."


def test_installation_default_is_used_when_nothing_else_applies(env) -> None:
    client, _ = env
    headers = auth_headers(client)

    updated = client.put(
        f"{API}/i18n/settings",
        json={"defaultLocale": "en", "timezone": "America/New_York", "currency": "USD"},
        headers=headers,
    )
    assert updated.status_code == 200, updated.text
    assert updated.json()["defaultLocale"] == "en"
    assert updated.json()["formats"] == {"timezone": "America/New_York", "currency": "USD"}

    assert client.post(f"{API}/auth/logout", headers=headers).status_code == 200
    response = client.get(f"{API}/auth/me")
    assert response.status_code == 401
    assert response.json()["error"]["message"] == "Authentication required."


def test_settings_require_system_configure_and_validate_installation_values(env) -> None:
    client, harness = env
    superadmin = auth_headers(client)

    created = client.post(
        f"{API}/identity/users",
        json={
            "username": "bea.admin",
            "name": "Bea Admin",
            "roleId": "admin",
            "password": SECOND_PASSWORD,
        },
        headers=superadmin,
    )
    assert created.status_code == 201, created.text
    administrator = auth_headers(client, "bea.admin", SECOND_PASSWORD)
    denied = client.put(
        f"{API}/i18n/settings",
        json={"defaultLocale": "en", "timezone": "America/New_York", "currency": "USD"},
        headers=administrator,
    )
    assert denied.status_code == 403, denied.text

    superadmin = auth_headers(client)
    bad_timezone = client.put(
        f"{API}/i18n/settings",
        json={"defaultLocale": "es", "timezone": "Bad/Zone", "currency": "PYG"},
        headers=superadmin,
    )
    assert bad_timezone.status_code == 422, bad_timezone.text
    assert bad_timezone.json()["error"]["key"] == "api.i18n.invalid_timezone"
    assert bad_timezone.json()["error"]["params"] == {"timezone": "Bad/Zone"}
    assert harness.scalar("SELECT timezone FROM identity_security_settings WHERE id = 1") in (
        None,
        "America/Asuncion",
    )

    bad_currency = client.put(
        f"{API}/i18n/settings",
        json={"defaultLocale": "es", "timezone": "America/Asuncion", "currency": "ZZZ"},
        headers=superadmin,
    )
    assert bad_currency.status_code == 422, bad_currency.text
    assert bad_currency.json()["error"]["key"] == "api.i18n.invalid_currency"
    stored = harness.sql(
        "SELECT session_minutes, default_locale, timezone, currency"
        " FROM identity_security_settings WHERE id = 1"
    )
    assert stored == [(480, "es", "America/Asuncion", "PYG")]

    unchanged = client.get(f"{API}/i18n/locales").json()
    assert unchanged["defaultLocale"] == "es"
    assert unchanged["formats"] == {"timezone": "America/Asuncion", "currency": "PYG"}


def test_preference_patch_requires_csrf_and_leaves_the_preference_unchanged(env) -> None:
    client, _ = env
    auth_headers(client)

    missing_csrf = client.patch(
        f"{API}/auth/me/preferences",
        json={"locale": "en"},
        headers={"Origin": ORIGIN},
    )
    assert missing_csrf.status_code == 403, missing_csrf.text
    assert missing_csrf.json()["error"]["key"] == "api.auth.csrf_invalid"

    current = client.get(f"{API}/auth/me")
    assert current.status_code == 200, current.text
    assert current.json()["preferences"] == {"locale": None}
    assert current.json()["locale"] == "es"


def test_validation_envelope_is_localized_with_key_and_params(env) -> None:
    client, _ = env

    english = client.post(
        f"{API}/auth/login",
        json={"username": "", "password": "x"},
        headers={"Origin": ORIGIN, "Accept-Language": "en"},
    )
    assert english.status_code == 422, english.text
    body = english.json()["error"]
    assert body["code"] == "validation_error"
    assert body["key"] == "api.error.validation_error"
    assert body["message"] == "Request validation failed."
    detail = english.json()["details"][0]
    assert detail["field"] == "username"
    assert detail["key"] == "api.validation.string_too_short"
    assert detail["params"] == {"min_length": 1}
    assert detail["message"] == "Must be at least 1 characters."

    spanish = client.post(
        f"{API}/auth/login",
        json={"username": "", "password": "x"},
        headers={"Origin": ORIGIN, "Accept-Language": "es"},
    )
    assert spanish.status_code == 422, spanish.text
    detail = spanish.json()["details"][0]
    assert detail["key"] == "api.validation.string_too_short"
    assert detail["message"] == "Debe tener al menos 1 caracteres."


def test_existing_envelope_fields_are_unchanged(env) -> None:
    client, _ = env
    headers = auth_headers(client)

    current = client.get(f"{API}/auth/me")
    assert current.status_code == 200, current.text
    payload = current.json()
    assert {"user", "permissions", "csrfToken", "sessionMinutes", "demoMode"} <= set(payload)
    assert payload["sessionMinutes"] == 480
    assert payload["demoMode"] is False
    assert {"id", "username", "name", "email", "roleId", "active", "lastAccess"} <= set(
        payload["user"]
    )

    error = client.get(f"{API}/auth/me", headers={"Authorization": "Bearer not-a-token"})
    assert error.status_code == 401
    assert {"code", "message"} <= set(error.json()["error"])

    logout = client.post(f"{API}/auth/logout", headers=headers)
    assert logout.status_code == 200


def test_logout_requires_csrf(env) -> None:
    client, _ = env
    auth_headers(client)

    refused = client.post(f"{API}/auth/logout", headers={"Origin": ORIGIN})
    assert refused.status_code == 403, refused.text
    assert refused.json()["error"]["key"] == "api.auth.csrf_invalid"

    still_signed_in = client.get(f"{API}/auth/me")
    assert still_signed_in.status_code == 200


def test_public_catalogs_are_reachable_in_demo_mode_without_authentication(
    settings_factory: Callable[..., Settings],
) -> None:
    import os

    from itsm.demo.seed import seed
    from itsm.release_mode import RELEASE_MODE_ENV
    from sqlalchemy.orm import Session

    settings = settings_factory()
    assert run_migrations(settings).returncode == 0
    engine = create_engine_from_settings(settings)
    try:
        with Session(engine) as session:
            seed(session, settings, "demo.owner", "Demo-Installer-Pass-2026")
    finally:
        engine.dispose()

    previous = os.environ.get(RELEASE_MODE_ENV)
    os.environ[RELEASE_MODE_ENV] = "demo"
    client: TestClient | None = None
    try:
        client = TestClient(create_app(settings))
        client.__enter__()
    finally:
        if previous is None:
            os.environ.pop(RELEASE_MODE_ENV, None)
        else:
            os.environ[RELEASE_MODE_ENV] = previous
    try:
        locales = client.get(f"{API}/i18n/locales")
        assert locales.status_code == 200, locales.text
        bundle = client.get(f"{API}/i18n/bundle", params={"locale": "en"})
        assert bundle.status_code == 200, bundle.text
        assert bundle.json()["messages"]["api.error.not_found"] == "Not found."

        visitor = login(client, "admin", "admin")
        assert visitor.status_code == 200, visitor.text
        visitor_headers = {"Origin": ORIGIN, "X-CSRF-Token": str(visitor.json()["csrfToken"])}
        denied = client.put(
            f"{API}/i18n/settings",
            json={"defaultLocale": "en", "timezone": "America/New_York", "currency": "USD"},
            headers=visitor_headers,
        )
        assert denied.status_code == 403, denied.text
    finally:
        client.__exit__(None, None, None)


def test_public_i18n_endpoints_stay_open_in_demo_mode(
    settings_factory: Callable[..., Settings],
) -> None:
    """The login/demo selector needs the catalogs before any session exists."""
    settings = settings_factory()
    assert run_migrations(settings).returncode == 0
    engine = create_engine_from_settings(settings)
    try:
        with Session(engine) as session:
            session.add(
                DemoInstallation(id=1, dataset="fictional-infrastructure-v1", created_at=utcnow())
            )
            session.commit()
    finally:
        engine.dispose()

    previous = os.environ.get(RELEASE_MODE_ENV)
    os.environ[RELEASE_MODE_ENV] = "demo"
    try:
        with TestClient(create_app(settings)) as client:
            locales = client.get(f"{API}/i18n/locales")
            bundle = client.get(f"{API}/i18n/bundle", params={"locale": "en"})
            settings_write = client.put(
                f"{API}/i18n/settings",
                json={"defaultLocale": "en", "timezone": "America/New_York", "currency": "USD"},
                headers={"Origin": ORIGIN},
            )
    finally:
        if previous is None:
            os.environ.pop(RELEASE_MODE_ENV, None)
        else:
            os.environ[RELEASE_MODE_ENV] = previous

    assert locales.status_code == 200, locales.text
    assert locales.json()["defaultLocale"] == "es"
    assert bundle.status_code == 200, bundle.text
    assert bundle.json()["messages"]["api.error.not_found"] == "Not found."
    assert settings_write.status_code == 401, settings_write.text


def test_accept_language_honors_quality_values_and_exclusions() -> None:
    """F1: q=0 excludes a tag and the highest q wins, ties in header order."""
    from itsm.i18n.request import negotiate_accept_language

    available = ("es", "en")

    assert negotiate_accept_language("en;q=0", available) is None
    assert negotiate_accept_language("es;q=0.1, en;q=0.9", available) == "en"
    assert negotiate_accept_language("en;q=0.5, es;q=0.5", available) == "en"
    assert negotiate_accept_language("es;q=0.3, en;q=0.9, es-PY;q=0.4", available) == "en"
    assert negotiate_accept_language("*,en;q=0.2", available) == "en"


def test_accept_language_matches_hyphenated_installed_pack_tags() -> None:
    from itsm.i18n.request import negotiate_accept_language

    available = ("es", "en", "pt-br")
    assert negotiate_accept_language("pt-BR", available) == "pt-br"
    assert negotiate_accept_language("pt-BR,pt;q=0.9", available) == "pt-br"
    assert negotiate_accept_language("en-US", available) == "en"
    assert negotiate_accept_language("fr", available) is None


def test_accept_language_exclusion_reaches_the_http_error_locale(env) -> None:
    client, _ = env

    response = client.get(
        f"{API}/auth/me",
        headers={"Accept-Language": "en;q=0"},
    )

    assert response.status_code == 401
    assert response.json()["error"]["message"] == "Se requiere autenticación."


def test_bundle_etag_and_fallback_change_with_the_default_locale(env) -> None:
    """F2: the ETag covers the fallback chain, so a 304 never serves a stale list."""
    client, _ = env
    headers = auth_headers(client)

    before = client.get(f"{API}/i18n/bundle", params={"locale": "es"})
    assert before.status_code == 200, before.text
    assert before.json()["fallback"] == ["es"]
    etag = before.headers["etag"]

    updated = client.put(
        f"{API}/i18n/settings",
        json={"defaultLocale": "en", "timezone": "America/Asuncion", "currency": "PYG"},
        headers=headers,
    )
    assert updated.status_code == 200, updated.text
    assert updated.json()["revision"] > before.json()["revision"]
    assert updated.json()["defaultLocale"] == "en"

    revalidated = client.get(
        f"{API}/i18n/bundle",
        params={"locale": "es"},
        headers={"If-None-Match": etag},
    )
    assert revalidated.status_code == 200, revalidated.text
    assert revalidated.json()["fallback"] == ["es", "en"]
    assert revalidated.headers["etag"] != etag
