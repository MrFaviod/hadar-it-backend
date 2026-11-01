"""Catalog registry: providers, monotonic revision and D5 precedence."""

from __future__ import annotations

from collections.abc import Callable, Iterator

import pytest
from itsm.config import Settings
from itsm.database import create_engine_from_settings, create_session_factory
from itsm.i18n import registry
from itsm.i18n.registry import LocaleName, ProviderPayload
from sqlalchemy import text
from tests.conftest import run_migrations


@pytest.fixture
def factory(settings_factory: Callable[..., Settings]) -> Iterator[Callable]:
    settings = settings_factory()
    applied = run_migrations(settings)
    assert applied.returncode == 0, applied.stderr
    engine = create_engine_from_settings(settings)
    session_factory = create_session_factory(engine)
    registry.configure(session_factory)
    try:
        yield session_factory
    finally:
        registry.reset()
        engine.dispose()


def extension_provider() -> ProviderPayload:
    return ProviderPayload(
        provider_id="software-licenses",
        kind="extension",
        version="1.0.0",
        locales=(LocaleName("es", "Spanish", "Español"),),
        catalogs={
            "es": {
                "ext.software-licenses.title": "Licencias",
                "ext.software-licenses.count": "{count} licencia | {count} licencias",
            }
        },
    )


def pack(
    provider_id: str,
    *,
    priority: int = 0,
    review_status: str = "reviewed",
    version: str = "1.0.0",
    catalogs: dict[str, dict[str, str]] | None = None,
    overrides: tuple[str, ...] = (),
    locales: tuple[LocaleName, ...] | None = None,
) -> ProviderPayload:
    catalog = catalogs or {"pt-br": {"ext.software-licenses.title": "Licenças"}}
    return ProviderPayload(
        provider_id=provider_id,
        kind="language-pack",
        version=version,
        priority=priority,
        review_status=review_status,
        locales=locales or (LocaleName("pt-BR", "Portuguese (Brazil)", "Português (Brasil)"),),
        catalogs=catalog,
        overrides=overrides,
    )


def write(session_factory, payload: ProviderPayload) -> None:
    with session_factory() as session:
        registry.write_provider(session, payload)
        session.commit()


def message(key: str, locale: str, default_locale: str = "es") -> str | None:
    hit = registry.lookup(key, locale, default_locale)
    return None if hit is None else hit[0]


def test_revision_starts_at_zero_and_never_decreases(factory) -> None:
    with factory() as session:
        assert registry.revision(session) == 0
        registry.write_provider(session, extension_provider())
        session.commit()
        assert registry.revision(session) == 1
        registry.write_provider(session, pack("pt-br-pack"))
        session.commit()
        assert registry.revision(session) == 2
        registry.set_review_status(session, "pt-br-pack", "draft")
        session.commit()
        assert registry.revision(session) == 3
        assert registry.delete_provider(session, "pt-br-pack") is True
        session.commit()
        assert registry.revision(session) == 4
        assert registry.delete_provider(session, "pt-br-pack") is False
        assert registry.revision(session) == 4


def test_owner_catalog_wins_over_a_fill_only_pack_entry(factory) -> None:
    write(factory, extension_provider())
    write(
        factory,
        pack(
            "filler",
            catalogs={"es-PY": {"ext.software-licenses.title": "Ignorado"}},
            locales=(LocaleName("es-PY", "Spanish (Paraguay)", "Español (Paraguay)"),),
        ),
    )

    assert message("ext.software-licenses.title", "es") == "Licencias"
    assert message("ext.software-licenses.title", "es-PY") == "Ignorado"


def test_explicit_override_beats_the_owner_and_higher_priority_wins(factory) -> None:
    write(factory, extension_provider())
    write(
        factory,
        pack(
            "low",
            priority=1,
            overrides=("ext.software-licenses.title",),
            catalogs={"es": {"ext.software-licenses.title": "Bajo"}},
            locales=(LocaleName("es", "Spanish", "Español"),),
        ),
    )
    assert message("ext.software-licenses.title", "es") == "Bajo"

    write(
        factory,
        pack(
            "high",
            priority=9,
            overrides=("ext.software-licenses.title",),
            catalogs={"es": {"ext.software-licenses.title": "Alto"}},
            locales=(LocaleName("es", "Spanish", "Español"),),
        ),
    )
    assert message("ext.software-licenses.title", "es") == "Alto"


def test_equal_priority_is_resolved_by_lexical_provider_id(factory) -> None:
    write(factory, extension_provider())
    write(
        factory,
        pack(
            "alfa",
            overrides=("ext.software-licenses.title",),
            catalogs={"es": {"ext.software-licenses.title": "Alfa"}},
            locales=(LocaleName("es", "Spanish", "Español"),),
        ),
    )
    write(
        factory,
        pack(
            "beta",
            overrides=("ext.software-licenses.title",),
            catalogs={"es": {"ext.software-licenses.title": "Beta"}},
            locales=(LocaleName("es", "Spanish", "Español"),),
        ),
    )

    assert message("ext.software-licenses.title", "es") == "Beta"


def test_installation_custom_translation_wins_over_everything(factory) -> None:
    write(factory, extension_provider())
    write(
        factory,
        pack(
            "overrider",
            priority=9,
            overrides=("ext.software-licenses.title",),
            catalogs={"es": {"ext.software-licenses.title": "Paquete"}},
            locales=(LocaleName("es", "Spanish", "Español"),),
        ),
    )
    with factory() as session:
        session.execute(
            text(
                "INSERT INTO i18n_custom_translations (locale, key, value, updated_at)"
                " VALUES ('es', 'ext.software-licenses.title', 'Propia', '2026-11-01T00:00:00Z')"
            )
        )
        session.commit()

    with factory() as session:
        snapshot = registry.snapshot(session)
    view = snapshot.locale_view("es")
    assert view.messages["ext.software-licenses.title"] == "Propia"
    assert view.overrides["ext.software-licenses.title"] == "Propia"


def test_pack_locales_join_the_installation_and_fallback_chain(factory) -> None:
    write(factory, extension_provider())
    write(factory, pack("pt-br-pack"))

    with factory() as session:
        snapshot = registry.snapshot(session)

    assert snapshot.tags == ("es", "en", "pt-br")
    descriptors = {item["tag"]: item for item in snapshot.descriptors}
    assert descriptors["es"]["provider"] == "core"
    assert descriptors["pt-BR"]["provider"] == "pt-br-pack"
    assert descriptors["pt-BR"]["nativeName"] == "Português (Brasil)"
    assert snapshot.fallback("pt-br", "es") == ("pt-br", "es")
    assert snapshot.fallback("pt-br", "en") == ("pt-br", "en", "es")


def test_draft_packs_install_but_stay_inactive(factory) -> None:
    write(factory, extension_provider())
    write(
        factory,
        pack(
            "draft-pack",
            review_status="draft",
            catalogs={"de": {"ext.software-licenses.title": "Lizenzen"}},
            locales=(LocaleName("de", "German", "Deutsch"),),
        ),
    )

    with factory() as session:
        snapshot = registry.snapshot(session)
    assert "de" not in snapshot.tags
    # The inactive pack is not consulted: the Spanish owner text is what remains.
    assert message("ext.software-licenses.title", "de") == "Licencias"

    with factory() as session:
        assert registry.set_review_status(session, "draft-pack", "reviewed") is True
        session.commit()
    with factory() as session:
        snapshot = registry.snapshot(session)
    assert "de" in snapshot.tags
    assert snapshot.locale_view("de").messages["ext.software-licenses.title"] == "Lizenzen"


def test_update_and_uninstall_recompute_the_view_and_restore_the_earlier_text(factory) -> None:
    write(factory, extension_provider())
    write(
        factory,
        pack(
            "pt-br-pack",
            overrides=("ext.software-licenses.title",),
            catalogs={"es": {"ext.software-licenses.title": "Licenças"}},
            locales=(LocaleName("es", "Spanish", "Español"),),
        ),
    )
    assert message("ext.software-licenses.title", "es") == "Licenças"

    write(
        factory,
        pack(
            "pt-br-pack",
            version="1.1.0",
            overrides=("ext.software-licenses.title",),
            catalogs={"es": {"ext.software-licenses.title": "Licenças v2"}},
            locales=(LocaleName("es", "Spanish", "Español"),),
        ),
    )
    assert message("ext.software-licenses.title", "es") == "Licenças v2"

    with factory() as session:
        registry.delete_provider(session, "pt-br-pack")
        session.commit()

    assert message("ext.software-licenses.title", "es") == "Licencias"
    with factory() as session:
        assert registry.provider_count(session, "language-pack") == 0
        owner = session.execute(
            text(
                "SELECT value FROM i18n_provider_catalogs WHERE provider_id = 'software-licenses'"
                " AND locale = 'es' AND key = 'ext.software-licenses.title'"
            )
        ).scalar_one()
    assert owner == "Licencias"


def test_docs_are_resolved_by_locale_and_topic_with_fallback(factory) -> None:
    write(
        factory,
        pack(
            "pt-br-pack",
            catalogs={"pt-br": {"api.demo.hello": "Olá"}},
            locales=(
                LocaleName("pt-BR", "Portuguese (Brazil)", "Português (Brasil)"),
                LocaleName("pt", "Portuguese", "Português"),
            ),
        ),
    )
    with factory() as session:
        registry.write_docs(
            session,
            "pt-br-pack",
            {"pt-BR": {"getting-started": "Comece aqui"}, "en": {"getting-started": "Start here"}},
        )
        session.commit()

    with factory() as session:
        hit = registry.resolve_doc(session, "pt-BR", "getting-started", "es")
        assert hit is not None
        assert hit.locale == "pt-BR"
        assert hit.provider == "pt-br-pack"
        assert hit.content == "Comece aqui"

        fallback = registry.resolve_doc(session, "pt-PT", "getting-started", "en")
        assert fallback is not None
        assert fallback.locale == "en"
        assert fallback.content == "Start here"

        assert registry.resolve_doc(session, "pt-BR", "missing-topic", "es") is None
