"""Message catalogs: parity, context coverage, plural forms and fallback."""

from __future__ import annotations

import json
import logging
import re
from datetime import UTC, datetime
from pathlib import Path

from itsm.i18n import (
    CATALOG_DIR,
    CORE_LOCALES,
    format_currency,
    format_datetime,
    format_number,
    t,
)

PLACEHOLDER = re.compile(r"\{([A-Za-z_][A-Za-z0-9_]*)\}")


def read_catalog(locale: str) -> dict[str, str]:
    path = Path(CATALOG_DIR) / f"{locale}.json"
    return json.loads(path.read_text(encoding="utf-8"))


def placeholders(template: str) -> set[str]:
    return set(PLACEHOLDER.findall(template))


def test_catalog_key_sets_and_parameter_names_match() -> None:
    catalogs = {locale: read_catalog(locale) for locale in CORE_LOCALES}

    reference = set(catalogs[CORE_LOCALES[0]])
    for locale, catalog in catalogs.items():
        assert set(catalog) == reference, locale

    for key in sorted(reference):
        expected = placeholders(catalogs[CORE_LOCALES[0]][key])
        for locale, catalog in catalogs.items():
            assert placeholders(catalog[key]) == expected, (locale, key)


def test_every_catalog_key_has_a_translator_context_entry() -> None:
    context = json.loads((Path(CATALOG_DIR) / "context.json").read_text(encoding="utf-8"))

    for key in read_catalog(CORE_LOCALES[0]):
        assert key in context, key
        assert context[key].strip(), key


def test_named_parameters_render_in_the_requested_locale() -> None:
    assert t("api.i18n.locale_count", "es", count=1) == "1 idioma instalado"
    assert t("api.i18n.locale_count", "es", count=2) == "2 idiomas instalados"
    assert t("api.i18n.locale_count", "en", count=2) == "2 languages installed"


def test_plural_forms_follow_the_requested_locale_categories() -> None:
    # Portuguese-Brazil uses the ``one``/``other`` split too; the text comes from
    # the Spanish fallback because no pt-BR catalog is installed yet.
    assert t("api.i18n.locale_count", "pt_BR", count=1) == "1 idioma instalado"
    assert t("api.i18n.locale_count", "pt_BR", count=2) == "2 idiomas instalados"


def test_fallback_chain_uses_parent_then_default_then_spanish() -> None:
    assert t("api.error.not_found", "en") == "Not found."
    assert t("api.error.not_found", "en_GB") == "Not found."
    assert t("api.error.not_found", "pt_BR") == "No encontrado."
    assert t("api.error.not_found", "pt_BR", default_locale="en") == "Not found."


def test_missing_key_is_localized_and_never_returns_the_key(caplog) -> None:
    missing = "api.i18n.missing.example"
    with caplog.at_level(logging.WARNING, logger="itsm.i18n"):
        first = t(missing, "es")
        second = t(missing, "es")

    assert first == "Texto no disponible."
    assert second == first
    assert missing not in first
    logged = [record for record in caplog.records if missing in record.getMessage()]
    assert len(logged) == 1


def test_formatting_helpers_use_babel_with_installation_values() -> None:
    assert format_number(1234.5, "es") == "1.234,5"
    assert format_currency(1000, "es", "PYG") == "1.000\u00a0PYG"
    moment = datetime(2026, 3, 1, 12, 0, tzinfo=UTC)
    assert format_datetime(moment, "en", "America/Asuncion") == "Mar 1, 2026, 9:00:00\u202fAM"


def test_camel_case_parameters_and_json_literals_keep_their_meaning() -> None:
    from itsm.i18n.messages import render
    from itsm.i18n.packs import placeholder_names

    sample = '{"api.assets.created": "Asset created"}'
    assert placeholder_names("{cacheRead} {noData} {detectedAt} {alertId}") == {
        "cacheRead",
        "noData",
        "detectedAt",
        "alertId",
    }
    assert (
        render("{cacheRead}/{alertId}/{unknown}", "en", {"cacheRead": 2, "alertId": "a"})
        == "2/a/{unknown}"
    )
    assert placeholder_names(sample) == set()
    assert render(sample, "en", {}) == sample


def test_literal_json_survives_render_with_whitespace_and_pipes() -> None:
    from itsm.i18n.messages import render
    from itsm.i18n.packs import is_literal_json_message, placeholder_names, plural_forms

    sample = '{ "rows": "a|b", "alert": "{alertId}|{bad-name}" }'
    assert is_literal_json_message(sample)
    assert placeholder_names(sample) == set()
    assert plural_forms(sample) == (sample,)
    assert render(sample, "en", {"count": 2}) == sample
