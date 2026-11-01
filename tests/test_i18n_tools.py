"""Translator tools (T7/S9): sources, coverage, export, import, validation.

Every case goes through the public HTTP surface. A rejected write must leave the
stored custom layer *and* the registry revision unchanged, so the assertions
read the database directly as well as the bundle the browser would receive.
"""

from __future__ import annotations

import io
import json
from collections.abc import Callable, Iterator
from typing import Any

import pytest
from babel.messages import pofile
from fastapi.testclient import TestClient
from itsm.config import Settings
from itsm.database import create_engine_from_settings
from itsm.i18n import registry
from itsm.i18n.catalog import CATALOG_DIR
from itsm.i18n.registry import LocaleName, ProviderPayload
from itsm.main import create_app
from tests.conftest import run_migrations
from tests.identity_support import Harness

ORIGIN = "http://testserver"
API = "/api/v1"
ADMIN_PASSWORD = "installer-password-2026"
SECOND_PASSWORD = "second-admin-password-2026"

UI_ES = {
    "ui.dashboard.title": "Panel",
    "ui.dashboard.count": "{count} activo | {count} activos",
    "ui.login.submit": "Ingresar",
}
UI_EN = {
    "ui.dashboard.title": "Dashboard",
    "ui.dashboard.count": "{count} active | {count} active items",
    "ui.login.submit": "Sign in",
}
UI_CONTEXT = {
    "ui.dashboard.title": "Dashboard page heading.",
    "ui.dashboard.count": "Asset count badge in the dashboard cards.",
    "ui.login.submit": "Submit button on the login form.",
}


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
            registry.reset()
            harness.close()


def auth_headers(
    client: TestClient, username: str = "ana.admin", password: str = ADMIN_PASSWORD
) -> dict[str, str]:
    response = client.post(
        f"{API}/auth/login",
        json={"username": username, "password": password},
        headers={"Origin": ORIGIN},
    )
    assert response.status_code == 200, response.text
    return {"Origin": ORIGIN, "X-CSRF-Token": str(response.json()["csrfToken"])}


def add_admin(client: TestClient, superadmin: dict[str, str]) -> dict[str, str]:
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
    return auth_headers(client, "bea.admin", SECOND_PASSWORD)


def revision(harness: Harness) -> int:
    value = harness.scalar("SELECT revision FROM i18n_registry_state WHERE id = 1")
    return 0 if value is None else int(value)


def custom_rows(harness: Harness) -> list[tuple[Any, ...]]:
    return harness.sql(
        "SELECT locale, key, value FROM i18n_custom_translations ORDER BY locale, key"
    )


def register_ui(
    client: TestClient,
    headers: dict[str, str],
    *,
    catalogs: dict[str, dict[str, str]] | None = None,
    context: dict[str, str] | None = None,
):
    return client.put(
        f"{API}/i18n/sources/ui",
        json={
            "catalogs": catalogs if catalogs is not None else {"es": UI_ES, "en": UI_EN},
            "context": UI_CONTEXT if context is None else context,
        },
        headers=headers,
    )


def write_pack(client: TestClient, catalogs: dict[str, dict[str, str]]) -> None:
    factory = client.app.state.session_factory
    with factory() as session:
        registry.write_provider(
            session,
            ProviderPayload(
                provider_id="pt-br-pack",
                kind="language-pack",
                version="1.0.0",
                locales=(LocaleName("pt-BR", "Portuguese (Brazil)", "Português (Brasil)"),),
                catalogs=catalogs,
            ),
        )
        session.commit()


def import_catalog(
    client: TestClient,
    headers: dict[str, str],
    locale: str,
    entries: dict[str, str] | str,
    *,
    fmt: str = "json",
    dry_run: bool = False,
):
    content = entries if isinstance(entries, str) else json.dumps(entries, ensure_ascii=False)
    return client.post(
        f"{API}/i18n/import",
        json={"locale": locale, "format": fmt, "content": content, "dryRun": dry_run},
        headers=headers,
    )


def validate_catalog(
    client: TestClient,
    headers: dict[str, str],
    locale: str,
    entries: dict[str, str] | str,
    *,
    fmt: str = "json",
):
    content = entries if isinstance(entries, str) else json.dumps(entries, ensure_ascii=False)
    return client.post(
        f"{API}/i18n/validate",
        json={"locale": locale, "format": fmt, "content": content},
        headers=headers,
    )


def coverage(client: TestClient, headers: dict[str, str], **params: Any) -> dict[str, Any]:
    response = client.get(f"{API}/i18n/coverage", params=params, headers=headers)
    assert response.status_code == 200, response.text
    return response.json()


def locale_entry(payload: dict[str, Any], tag: str) -> dict[str, Any]:
    return next(entry for entry in payload["locales"] if entry["tag"] == tag)


# --------------------------------------------------------------- sources/ui
def test_ui_source_registration_is_idempotent_and_feeds_coverage(env) -> None:
    client, harness = env
    headers = auth_headers(client)
    core_total = len(json.loads((CATALOG_DIR / "es.json").read_text("utf-8")))

    first = register_ui(client, headers)

    assert first.status_code == 200, first.text
    body = first.json()
    assert body["source"] == "ui"
    assert body["changed"] is True
    assert body["locales"] == ["es", "en"]
    assert body["keys"] == len(UI_ES)
    assert body["revision"] == 1
    assert revision(harness) == 1
    assert len(body["digest"]) == 64

    again = register_ui(client, headers)
    assert again.status_code == 200, again.text
    assert again.json()["changed"] is False
    assert again.json()["digest"] == body["digest"]
    assert again.json()["revision"] == 1
    assert revision(harness) == 1

    payload = coverage(client, headers)
    assert payload["sourceLocale"] == "es"
    assert payload["source"]["total"] == core_total + len(UI_ES)
    assert payload["source"]["namespaces"]["ui"] == len(UI_ES)
    spanish = locale_entry(payload, "es")
    assert spanish["total"] == core_total + len(UI_ES)
    assert spanish["translated"] == spanish["total"]
    assert spanish["percentage"] == 100.0
    assert spanish["missing"]["items"] == []
    assert {"id": "ui", "kind": "ui-source", "entries": len(UI_ES)} in spanish["providers"]

    bundle = client.get(f"{API}/i18n/bundle", params={"locale": "es"})
    assert bundle.status_code == 200, bundle.text
    assert "ui.dashboard.title" not in bundle.json()["messages"]


def test_ui_source_rejects_foreign_namespaces_without_writing(env) -> None:
    client, harness = env
    headers = auth_headers(client)

    foreign = register_ui(
        client,
        headers,
        catalogs={"es": {"api.error.not_found": "No encontrado."}, "en": {}},
        context={},
    )
    assert foreign.status_code == 422, foreign.text
    error = foreign.json()["error"]
    assert error["key"] == "api.i18n.source_invalid"
    assert error["params"] == {"count": 1}
    problem = foreign.json()["report"]["problems"][0]
    assert problem["key"] == "api.error.not_found"
    assert problem["reason"] == "namespace_not_allowed"
    assert problem["reasonKey"] == "api.i18n.problem.namespace_not_allowed"
    assert revision(harness) == 0
    assert harness.sql("SELECT COUNT(*) FROM i18n_providers") == [(0,)]

    missing_source = register_ui(client, headers, catalogs={"en": UI_EN})
    assert missing_source.status_code == 422, missing_source.text
    reasons = {item["reason"] for item in missing_source.json()["report"]["problems"]}
    assert "source_locale_missing" in reasons

    unknown_context = register_ui(
        client, headers, catalogs={"es": UI_ES, "en": UI_EN}, context={"ui.missing.key": "x"}
    )
    assert unknown_context.status_code == 422, unknown_context.text
    reasons = {item["reason"] for item in unknown_context.json()["report"]["problems"]}
    assert "unknown_context" in reasons
    assert revision(harness) == 0


def test_source_writes_and_reads_enforce_permissions_and_csrf(env) -> None:
    client, harness = env
    assert client.get(f"{API}/i18n/coverage").status_code == 401
    superadmin = auth_headers(client)
    administrator = add_admin(client, superadmin)

    denied = register_ui(client, administrator)
    assert denied.status_code == 403, denied.text
    assert denied.json()["error"]["key"] == "api.identity.permission_denied"
    assert harness.sql("SELECT COUNT(*) FROM i18n_providers") == [(0,)]

    superadmin = auth_headers(client)
    no_csrf = client.put(
        f"{API}/i18n/sources/ui",
        json={"catalogs": {"es": UI_ES, "en": UI_EN}, "context": UI_CONTEXT},
        headers={"Origin": ORIGIN},
    )
    assert no_csrf.status_code == 403, no_csrf.text
    assert no_csrf.json()["error"]["key"] == "api.auth.csrf_invalid"
    assert revision(harness) == 0

    administrator = auth_headers(client, "bea.admin", SECOND_PASSWORD)
    read_denied = client.get(f"{API}/i18n/coverage", headers=administrator)
    assert read_denied.status_code == 403, read_denied.text
    export_denied = client.get(
        f"{API}/i18n/export", params={"locale": "es", "format": "json"}, headers=administrator
    )
    assert export_denied.status_code == 403, export_denied.text


# ----------------------------------------------------------------- coverage
def test_coverage_reports_missing_keys_context_providers_and_orphans(env) -> None:
    client, harness = env
    headers = auth_headers(client)
    assert register_ui(client, headers).status_code == 200
    write_pack(
        client,
        {
            "pt-br": {
                "api.error.not_found": "Não encontrado.",
                "ui.dashboard.title": "Painel",
            }
        },
    )
    imported = import_catalog(
        client, headers, "pt-BR", {"api.error.unauthorized": "Não autorizado."}
    )
    assert imported.status_code == 200, imported.text

    payload = coverage(client, headers, locale="pt-BR", limit=5)
    assert payload["revision"] == revision(harness) == 3
    assert payload["page"] == {"limit": 5, "offset": 0}
    portuguese = locale_entry(payload, "pt-br")
    assert portuguese["displayTag"] == "pt-BR"
    assert portuguese["localeProvider"] == "pt-br-pack"
    assert portuguese["source"] is False
    assert portuguese["total"] == payload["source"]["total"]
    assert portuguese["translated"] == 3
    assert portuguese["percentage"] == round(3 * 100 / payload["source"]["total"], 2)
    assert {"id": "pt-br-pack", "kind": "language-pack", "entries": 2} in portuguese["providers"]
    assert {"id": "custom", "kind": "custom", "entries": 1} in portuguese["providers"]
    assert portuguese["custom"] == {"entries": 1, "orphaned": []}

    missing = portuguese["missing"]
    assert missing["limit"] == 5
    assert missing["offset"] == 0
    assert missing["total"] == portuguese["total"] - 3
    assert len(missing["items"]) == 5
    assert [item["key"] for item in missing["items"]] == sorted(
        item["key"] for item in missing["items"]
    )
    context = json.loads((CATALOG_DIR / "context.json").read_text("utf-8"))
    first_api = next(item for item in missing["items"] if item["key"].startswith("api."))
    assert first_api["context"] == context[first_api["key"]]

    page_two = locale_entry(coverage(client, headers, locale="pt-BR", limit=5, offset=5), "pt-br")
    assert page_two["missing"]["offset"] == 5
    assert page_two["missing"]["items"][0]["key"] != missing["items"][0]["key"]

    ui_only = coverage(client, headers, namespace="ui")
    assert ui_only["namespace"] == "ui"
    assert ui_only["source"]["total"] == len(UI_ES)
    assert locale_entry(ui_only, "es")["percentage"] == 100.0
    assert locale_entry(ui_only, "en")["percentage"] == 100.0
    assert locale_entry(ui_only, "pt-br")["translated"] == 1

    unknown = client.get(f"{API}/i18n/coverage", params={"locale": "xx"}, headers=headers)
    assert unknown.status_code == 404
    assert unknown.json()["error"]["key"] == "api.i18n.unknown_locale"

    bad_namespace = client.get(
        f"{API}/i18n/coverage", params={"namespace": "bad namespace!"}, headers=headers
    )
    assert bad_namespace.status_code == 422
    assert bad_namespace.json()["error"]["key"] == "api.i18n.invalid_namespace"


# ------------------------------------------------------------------- export
def test_export_json_and_po_download_for_one_locale(env) -> None:
    client, _harness = env
    headers = auth_headers(client)
    assert register_ui(client, headers).status_code == 200
    assert (
        import_catalog(client, headers, "en", {"api.error.not_found": "Not here."}).status_code
        == 200
    )

    exported = client.get(
        f"{API}/i18n/export",
        params={"locale": "en", "format": "json", "namespace": "api"},
        headers=headers,
    )
    assert exported.status_code == 200, exported.text
    assert exported.headers["content-type"].startswith("application/json")
    assert 'filename="en.api.json"' in exported.headers["content-disposition"]
    document = exported.json()
    assert document["api.error.not_found"] == "Not here."
    assert all(key.startswith("api.") for key in document)

    english_ui = client.get(
        f"{API}/i18n/export",
        params={"locale": "en", "format": "json", "namespace": "ui"},
        headers=headers,
    )
    assert english_ui.status_code == 200, english_ui.text
    assert english_ui.json() == UI_EN

    po = client.get(
        f"{API}/i18n/export",
        params={"locale": "en", "format": "po", "namespace": "api"},
        headers=headers,
    )
    assert po.status_code == 200, po.text
    assert po.headers["content-type"].startswith("text/x-gettext-translation")
    assert 'filename="en.api.po"' in po.headers["content-disposition"]
    parsed = pofile.read_po(io.BytesIO(po.content))
    source = json.loads((CATALOG_DIR / "es.json").read_text("utf-8"))
    message = next(item for item in parsed if item.context == "api.error.not_found")
    assert message.id == source["api.error.not_found"]
    assert message.string == "Not here."
    context = json.loads((CATALOG_DIR / "context.json").read_text("utf-8"))
    assert context["api.error.not_found"] in (message.auto_comments or [])

    unknown = client.get(
        f"{API}/i18n/export", params={"locale": "xx", "format": "json"}, headers=headers
    )
    assert unknown.status_code == 404
    assert unknown.json()["error"]["key"] == "api.i18n.unknown_locale"

    unsupported = client.get(
        f"{API}/i18n/export", params={"locale": "en", "format": "csv"}, headers=headers
    )
    assert unsupported.status_code == 422
    assert unsupported.json()["error"]["key"] == "api.i18n.unsupported_format"
    assert unsupported.json()["error"]["params"] == {"format": "csv"}


# ------------------------------------------------------------------- import
def test_import_json_writes_the_custom_layer_and_wins_precedence(env) -> None:
    client, harness = env
    headers = auth_headers(client)
    before = client.get(f"{API}/i18n/bundle", params={"locale": "en"})
    etag = before.headers["etag"]

    imported = import_catalog(client, headers, "en", {"api.error.not_found": "Not here."})

    assert imported.status_code == 200, imported.text
    report = imported.json()
    assert report["valid"] is True
    assert report["entries"] == 1
    assert report["applied"] == 1
    assert report["problems"] == []
    assert report["dryRun"] is False
    assert report["revision"] == revision(harness) == 1
    assert custom_rows(harness) == [("en", "api.error.not_found", "Not here.")]

    audit = harness.sql(
        "SELECT action, resource, outcome FROM identity_audit_events"
        " WHERE action = 'i18n.custom_imported'"
    )
    assert audit == [("i18n.custom_imported", "i18n:custom:en", "success")]

    bundle = client.get(f"{API}/i18n/bundle", params={"locale": "en"})
    assert bundle.status_code == 200, bundle.text
    assert bundle.json()["overrides"]["api.error.not_found"] == "Not here."
    assert bundle.json()["messages"]["api.error.not_found"] == "Not here."
    assert bundle.headers["etag"] != etag
    stale = client.get(
        f"{API}/i18n/bundle", params={"locale": "en"}, headers={"If-None-Match": etag}
    )
    assert stale.status_code == 200

    repeated = import_catalog(client, headers, "en", {"api.error.not_found": "Not here."})
    assert repeated.status_code == 200, repeated.text
    assert repeated.json()["applied"] == 0
    assert revision(harness) == 1

    dry_run = import_catalog(
        client, headers, "en", {"api.error.not_found": "Not there."}, dry_run=True
    )
    assert dry_run.status_code == 200, dry_run.text
    assert dry_run.json()["dryRun"] is True
    assert dry_run.json()["applied"] == 0
    assert revision(harness) == 1
    assert custom_rows(harness) == [("en", "api.error.not_found", "Not here.")]


def test_import_reports_every_problem_and_writes_nothing(env) -> None:
    client, harness = env
    headers = auth_headers(client)
    assert (
        import_catalog(client, headers, "en", {"api.error.not_found": "Not here."}).status_code
        == 200
    )
    stored = custom_rows(harness)
    stored_revision = revision(harness)

    content = (
        "{"
        '"api.error.not_found": "Not here.",'
        '"api.error.not_found": "Not here either.",'
        '"api.error.unauthorized": "Not allowed.",'
        '"api.i18n.locale_count": "{count} language | {count} languages | {count} langs",'
        '"api.unknown.key": "Unknown",'
        '"api.error.forbidden": "   ",'
        '"api.error.bad_request": "Bad {name",'
        '"api.error.conflict": "Conflict {other}"'
        "}"
    )
    response = import_catalog(client, headers, "en", content)

    assert response.status_code == 422, response.text
    error = response.json()["error"]
    assert error["code"] == "validation_error"
    assert error["key"] == "api.i18n.import_invalid"
    assert error["params"] == {"count": 6}
    report = response.json()["report"]
    assert report["valid"] is False
    assert report["applied"] == 0
    reasons = {(item["key"], item["reason"]) for item in report["problems"]}
    assert ("api.unknown.key", "unknown_key") in reasons
    assert ("api.error.forbidden", "empty_text") in reasons
    assert ("api.error.conflict", "parameters_mismatch") in reasons
    assert ("api.error.bad_request", "malformed_message") in reasons
    assert ("api.i18n.locale_count", "plural_forms_mismatch") in reasons
    assert ("api.error.not_found", "duplicate_key") in reasons
    assert all(
        item["reasonKey"] == f"api.i18n.problem.{item['reason']}" for item in report["problems"]
    )
    mismatch = next(item for item in report["problems"] if item["reason"] == "parameters_mismatch")
    assert mismatch["params"] == {"missing": "none", "unexpected": "other"}
    assert custom_rows(harness) == stored
    assert revision(harness) == stored_revision

    for item in report["problems"]:
        assert item["message"]
        assert "{" not in item["message"].replace("{count}", "").replace("{name}", "")


def test_import_po_skips_empty_translations_and_rejects_duplicates(env) -> None:
    client, harness = env
    headers = auth_headers(client)
    source = json.loads((CATALOG_DIR / "es.json").read_text("utf-8"))
    catalog = pofile.Catalog(locale="en", fuzzy=False, project="ITSM")
    catalog.add(
        source["api.error.not_found"],
        "Not here.",
        context="api.error.not_found",
        auto_comments=["Shown on a missing resource."],
    )
    catalog.add(source["api.error.unauthorized"], "", context="api.error.unauthorized")
    buffer = io.BytesIO()
    pofile.write_po(buffer, catalog)

    imported = import_catalog(client, headers, "en", buffer.getvalue().decode(), fmt="po")

    assert imported.status_code == 200, imported.text
    assert imported.json()["format"] == "po"
    assert imported.json()["entries"] == 1
    assert imported.json()["applied"] == 1
    assert custom_rows(harness) == [("en", "api.error.not_found", "Not here.")]

    duplicate = (
        'msgid ""\nmsgstr "Content-Type: text/plain; charset=UTF-8\\n"\n\n'
        f'msgctxt "api.error.not_found"\nmsgid "{source["api.error.not_found"]}"\n'
        'msgstr "Not here."\n\n'
        f'msgctxt "api.error.not_found"\nmsgid "{source["api.error.not_found"]}"\n'
        'msgstr "Not there."\n'
    )
    rejected = import_catalog(client, headers, "en", duplicate, fmt="po")
    assert rejected.status_code == 422, rejected.text
    reasons = {item["reason"] for item in rejected.json()["report"]["problems"]}
    assert "duplicate_key" in reasons
    assert custom_rows(harness) == [("en", "api.error.not_found", "Not here.")]

    malformed = import_catalog(client, headers, "en", "not a po file", fmt="po")
    assert malformed.status_code == 422, malformed.text
    assert malformed.json()["report"]["problems"][0]["reason"] == "invalid_po"

    unsupported = import_catalog(client, headers, "en", "{}", fmt="csv")
    assert unsupported.status_code == 422, unsupported.text
    assert unsupported.json()["error"]["key"] == "api.i18n.unsupported_format"
    assert revision(harness) == 1


# ----------------------------------------------------------------- validate
def test_validate_endpoint_returns_the_report_without_writing(env) -> None:
    client, harness = env
    headers = auth_headers(client)

    good = validate_catalog(client, headers, "en", {"api.error.not_found": "Not here."})
    assert good.status_code == 200, good.text
    assert good.json() == {
        "locale": "en",
        "format": "json",
        "valid": True,
        "dryRun": True,
        "entries": 1,
        "applied": 0,
        "problems": [],
        "revision": 0,
    }
    assert custom_rows(harness) == []

    bad = validate_catalog(client, headers, "en", {"api.unknown.key": "Unknown"})
    assert bad.status_code == 200, bad.text
    assert bad.json()["valid"] is False
    assert bad.json()["problems"][0]["reason"] == "unknown_key"
    assert revision(harness) == 0

    dry_run = import_catalog(client, headers, "en", {"api.unknown.key": "Unknown"}, dry_run=True)
    assert dry_run.status_code == 422, dry_run.text
    assert dry_run.json()["report"]["applied"] == 0
    assert custom_rows(harness) == []


def test_import_requires_system_configure_and_rejects_unknown_locales(env) -> None:
    client, harness = env
    superadmin = auth_headers(client)
    administrator = add_admin(client, superadmin)

    denied = import_catalog(client, administrator, "en", {"api.error.not_found": "Not here."})
    assert denied.status_code == 403, denied.text
    assert revision(harness) == 0

    superadmin = auth_headers(client)
    unknown = import_catalog(client, superadmin, "xx", {"api.error.not_found": "x"})
    assert unknown.status_code == 404, unknown.text
    assert unknown.json()["error"]["key"] == "api.i18n.unknown_locale"
    not_installed = import_catalog(client, superadmin, "pt-BR", {"api.error.not_found": "x"})
    assert not_installed.status_code == 404, not_installed.text
    assert custom_rows(harness) == []


# ------------------------------------------------------------------- delete
def test_delete_one_custom_key_then_reset_the_locale_layer(env) -> None:
    client, harness = env
    headers = auth_headers(client)
    assert (
        import_catalog(
            client,
            headers,
            "en",
            {"api.error.not_found": "Not here.", "api.error.unauthorized": "Not allowed."},
        ).status_code
        == 200
    )
    revision_after_import = revision(harness)

    removed = client.delete(f"{API}/i18n/custom/en/api.error.not_found", headers=headers)
    assert removed.status_code == 200, removed.text
    assert removed.json()["deleted"] == 1
    assert removed.json()["revision"] == revision_after_import + 1
    assert [row[1] for row in custom_rows(harness)] == ["api.error.unauthorized"]

    missing = client.delete(f"{API}/i18n/custom/en/api.error.not_found", headers=headers)
    assert missing.status_code == 404, missing.text
    assert missing.json()["error"]["key"] == "api.i18n.custom_key_not_found"
    assert missing.json()["error"]["params"] == {
        "locale": "en",
        "key": "api.error.not_found",
    }
    assert revision(harness) == revision_after_import + 1

    unknown = client.delete(f"{API}/i18n/custom/xx/api.error.not_found", headers=headers)
    assert unknown.status_code == 404, unknown.text
    assert unknown.json()["error"]["key"] == "api.i18n.unknown_locale"

    reset = client.delete(f"{API}/i18n/custom/en", headers=headers)
    assert reset.status_code == 200, reset.text
    assert reset.json()["deleted"] == 1
    assert reset.json()["revision"] == revision_after_import + 2
    assert custom_rows(harness) == []
    empty = client.delete(f"{API}/i18n/custom/en", headers=headers)
    assert empty.status_code == 200, empty.text
    assert empty.json()["deleted"] == 0
    assert revision(harness) == revision_after_import + 2

    assert (
        import_catalog(client, headers, "en", {"api.error.not_found": "Not here."}).status_code
        == 200
    )
    no_csrf = client.delete(f"{API}/i18n/custom/en/api.error.not_found", headers={"Origin": ORIGIN})
    assert no_csrf.status_code == 403, no_csrf.text
    assert len(custom_rows(harness)) == 1


# ------------------------------------------------------- survive core upgrade
def test_custom_translations_survive_a_core_upgrade_and_orphans_are_reported(
    env, monkeypatch
) -> None:
    client, _harness = env
    headers = auth_headers(client)
    assert (
        import_catalog(
            client,
            headers,
            "en",
            {
                "api.error.not_found": "Custom not found.",
                "api.i18n.locale_count": "Custom {count} language | Custom {count} languages",
                "api.error.unauthorized": "Custom unauthorized.",
            },
        ).status_code
        == 200
    )

    original = registry.load_catalog

    def upgraded(locale: str):
        catalog = original(locale)
        if catalog is None:
            return None
        changed = dict(catalog)
        changed["api.error.not_found"] = "Core 2.0 not found."
        changed.pop("api.i18n.locale_count", None)
        return changed

    monkeypatch.setattr(registry, "load_catalog", upgraded)

    bundle = client.get(f"{API}/i18n/bundle", params={"locale": "en"})
    assert bundle.status_code == 200, bundle.text
    assert bundle.json()["overrides"]["api.error.not_found"] == "Custom not found."
    assert bundle.json()["messages"]["api.error.not_found"] == "Custom not found."

    payload = coverage(client, headers, locale="en")
    english = locale_entry(payload, "en")
    orphaned = english["custom"]["orphaned"]
    assert [item["key"] for item in orphaned] == ["api.i18n.locale_count"]
    assert orphaned[0]["reason"] == "source_key_missing"
    assert orphaned[0]["reasonKey"] == "api.i18n.problem.source_key_missing"
    assert "api.i18n.locale_count" not in json.dumps(payload["source"])
    assert english["total"] == payload["source"]["total"]
    assert english["total"] == payload["source"]["total"]
