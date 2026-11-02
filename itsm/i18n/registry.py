"""The versioned catalog registry: providers, revision and D5 precedence.

Core files and extension packages are the *owners* of a key. A language pack
contributes two kinds of entries: an explicit `override` (which must be listed in
the pack manifest) wins over the owner, and a plain entry only fills a key the
installation does not have yet. Installation custom translations win over
everything.

Resolution order per ``(locale, key)`` (D5):

1. installation custom translation (T7 writes these rows);
2. pack entries listed in that pack's ``overrides``, higher ``priority`` first
   and, for equal priorities, the lexically greater package id;
3. the owner catalog (core for ``ui.*``/``api.*``, the extension for ``ext.<id>.*``);
4. non-overriding pack entries (fill only missing keys).

Nothing here edits an owner: every write only replaces the rows of one provider,
so an uninstall or an update recomputes the view and the earlier text returns.
"""

from __future__ import annotations

import hashlib
import json
import logging
import re
from collections.abc import Callable, Iterable, Mapping
from dataclasses import dataclass, field
from typing import Any, Final

from babel import Locale
from babel.core import UnknownLocaleError
from sqlalchemy import delete, func, select
from sqlalchemy.orm import Session

from itsm.i18n.catalog import (
    CORE_LOCALES,
    DEFAULT_LOCALE,
    load_catalog,
    locale_descriptor,
)
from itsm.i18n.models import (
    I18nCustomTranslation,
    I18nProvider,
    I18nProviderCatalog,
    I18nProviderDoc,
    I18nProviderLocale,
    I18nRegistryState,
    I18nSourceContext,
)

logger = logging.getLogger("itsm.i18n")

CORE_PROVIDER: Final[str] = "core"
EXTENSION: Final[str] = "extension"
LANGUAGE_PACK: Final[str] = "language-pack"
#: A provider that ships *source* text only (the frontend ``ui.*`` catalog).
#: It is deliberately inactive in the D5 overlay: the browser merges its own
#: built-in catalog, so the registration feeds coverage/validation, not serving.
UI_SOURCE: Final[str] = "ui-source"
UI_SOURCE_PROVIDER: Final[str] = "ui"
CUSTOM: Final[str] = "custom"
REVIEWED: Final[str] = "reviewed"
DRAFT: Final[str] = "draft"
REVIEW_STATUSES: Final[tuple[str, ...]] = (DRAFT, REVIEWED)

_TAG = re.compile(r"^[A-Za-z]{2,8}(?:-[A-Za-z0-9]{1,8})*$")


def canonical_tag(tag: str | None) -> str | None:
    """Normalize a locale tag for storage and lookup, or ``None`` when invalid."""
    if not tag:
        return None
    normalized = str(tag).strip().replace("_", "-")
    if not _TAG.match(normalized):
        return None
    canonical = normalized.lower()
    try:
        Locale.parse(canonical.replace("-", "_"))
    except UnknownLocaleError, ValueError:
        return None
    return canonical


def tag_chain(tag: str | None) -> tuple[str, ...]:
    """A tag and its parents, most specific first (``pt-br`` -> ``pt-br``, ``pt``)."""
    canonical = canonical_tag(tag)
    if canonical is None:
        return ()
    parts = canonical.split("-")
    chain: list[str] = []
    while parts:
        chain.append("-".join(parts))
        if len(parts) == 1:
            break
        parts = parts[:-1]
        # A script or region subtag is not a locale on its own.
        if len(parts[-1]) == 1:
            parts = parts[:-1]
    return tuple(chain)


@dataclass(frozen=True)
class LocaleName:
    """One locale a provider declares for the public selector."""

    tag: str
    name: str
    native_name: str


@dataclass(frozen=True)
class ProviderPayload:
    """Everything one installed provider contributes to the registry."""

    provider_id: str
    kind: str
    version: str
    priority: int = 0
    review_status: str = REVIEWED
    locales: tuple[LocaleName, ...] = ()
    catalogs: Mapping[str, Mapping[str, str]] = field(default_factory=dict)
    overrides: tuple[str, ...] = ()
    docs: Mapping[str, Mapping[str, str]] = field(default_factory=dict)


@dataclass(frozen=True)
class LocaleView:
    """The resolved view the bundle and ``t()`` serve for one locale."""

    tag: str
    messages: Mapping[str, str]
    overrides: Mapping[str, str]


@dataclass(frozen=True)
class DocHit:
    """One localized documentation topic and the pack that provided it."""

    locale: str
    topic: str
    content: str
    provider: str


@dataclass(frozen=True)
class Snapshot:
    """An immutable resolution of the whole registry at one revision."""

    revision: int
    tags: tuple[str, ...]
    locale_views: Mapping[str, LocaleView]
    descriptors: tuple[dict[str, str], ...]

    def resolve(self, tag: str | None) -> str | None:
        canonical = canonical_tag(tag)
        return canonical if canonical in self.locale_views else None

    def locale_view(self, tag: str) -> LocaleView:
        canonical = canonical_tag(tag)
        if canonical is None or canonical not in self.locale_views:
            raise KeyError(tag)
        return self.locale_views[canonical]

    def display_tag(self, canonical: str) -> str:
        for descriptor in self.descriptors:
            if canonical_tag(descriptor["tag"]) == canonical:
                return descriptor["tag"]
        return canonical

    def fallback(self, locale: str | None, default_locale: str = DEFAULT_LOCALE) -> tuple[str, ...]:
        """D5 chain restricted to installed locales: locale, parent, default, ``es``."""
        tags = list(self.tags)
        resolved: list[str] = []
        for candidate in (default_locale, DEFAULT_LOCALE):
            for tag in tag_chain(candidate):
                if tag in tags and tag not in resolved:
                    resolved.append(tag)
        requested = [tag for tag in tag_chain(locale) if tag in tags]
        chain = [*requested, *resolved]
        return tuple(dict.fromkeys(chain))


# --------------------------------------------------------------------------- #
# process-level configuration and snapshot cache
# --------------------------------------------------------------------------- #

_CONFIG: Callable[[], Session] | None = None
_CACHE: tuple[Any, int, Snapshot] | None = None


def configure(session_factory: Callable[[], Session]) -> None:
    """Bind the registry to one application session factory (idempotent)."""
    global _CONFIG, _CACHE
    if _CONFIG is session_factory:
        return
    _CONFIG = session_factory
    _CACHE = None


def reset() -> None:
    """Forget the configured factory and the cached snapshot (tests, shutdown)."""
    global _CONFIG, _CACHE
    _CONFIG = None
    _CACHE = None


def current_snapshot() -> Snapshot | None:
    """The cached snapshot, rebuilt when the stored revision moved on."""
    global _CACHE
    factory = _CONFIG
    if factory is None:
        return None
    try:
        with factory() as session:
            revision_number = revision(session)
            cached = _CACHE
            if cached is not None and cached[0] is factory and cached[1] == revision_number:
                return cached[2]
            built = snapshot(session)
    except Exception:  # pragma: no cover - defensive: never break message rendering
        logger.debug("i18n registry unavailable; serving owner catalogs", exc_info=True)
        return None
    _CACHE = (factory, revision_number, built)
    return built


def installed_tags() -> tuple[str, ...]:
    """Installed locale tags (core plus reviewed packs), canonical form."""
    snapshot = current_snapshot()
    return CORE_LOCALES if snapshot is None else snapshot.tags


def resolve_installed(tag: str | None) -> str | None:
    """Return the installed canonical tag for ``tag`` or ``None``."""
    snapshot = current_snapshot()
    if snapshot is None:
        from itsm.i18n.catalog import resolve_installed_locale

        core = resolve_installed_locale(tag)
        return None if core is None else canonical_tag(core)
    return snapshot.resolve(tag)


def effective_locale(tag: str | None, default_locale: str = DEFAULT_LOCALE) -> str:
    """The installed tag that serves a stored preference (D4/D5).

    A preference outlives the pack that provided it: uninstalling a pack never
    rewrites the stored choice, so the effective language comes from the
    remaining installed chain (parent locale first, then the installation
    default). Callers report the stored value separately; this is the locale
    every rendered artifact must use.
    """
    snapshot = current_snapshot()
    if snapshot is not None:
        chain = snapshot.fallback(tag if isinstance(tag, str) else None, default_locale)
        if chain:
            return chain[0]
        return DEFAULT_LOCALE
    for candidate in (tag, default_locale, DEFAULT_LOCALE):
        if not isinstance(candidate, str) or not candidate.strip():
            continue
        for parent in tag_chain(candidate):
            installed = resolve_installed(parent)
            if installed is not None:
                return installed
    return DEFAULT_LOCALE


def lookup(
    key: str, locale: str | None, default_locale: str = DEFAULT_LOCALE
) -> tuple[str, str] | None:
    """Resolve ``key`` through the registry; ``None`` means "not in the registry"."""
    snapshot = current_snapshot()
    if snapshot is None:
        return None
    for tag in snapshot.fallback(locale, default_locale):
        view = snapshot.locale_views.get(tag)
        if view is not None and key in view.messages:
            return view.messages[key], tag
    return None


# --------------------------------------------------------------------------- #
# writes
# --------------------------------------------------------------------------- #


def revision(session: Session) -> int:
    row = session.get(I18nRegistryState, 1)
    return 0 if row is None else int(row.revision)


def bump_revision(session: Session) -> int:
    """Advance the monotonic revision; every install/update/uninstall/review does."""
    row = session.get(I18nRegistryState, 1)
    if row is None:
        row = I18nRegistryState(id=1, revision=0)
        session.add(row)
    row.revision = int(row.revision) + 1
    session.flush()
    return int(row.revision)


def provider_count(session: Session, kind: str) -> int:
    return len(list(session.scalars(select(I18nProvider.id).where(I18nProvider.kind == kind))))


def write_provider(session: Session, payload: ProviderPayload) -> None:
    """Replace one provider's catalogs, locales and docs, then bump the revision."""
    if payload.kind not in (EXTENSION, LANGUAGE_PACK):
        raise ValueError(f"unknown provider kind: {payload.kind!r}")
    if payload.review_status not in REVIEW_STATUSES:
        raise ValueError(f"unknown review status: {payload.review_status!r}")

    row = session.get(I18nProvider, payload.provider_id)
    if row is None:
        row = I18nProvider(
            id=payload.provider_id,
            kind=payload.kind,
            version=payload.version,
            priority=payload.priority,
            review_status=payload.review_status,
        )
        session.add(row)
    else:
        row.kind = payload.kind
        row.version = payload.version
        row.priority = payload.priority
        row.review_status = payload.review_status
    session.flush()

    _replace_children(session, payload.provider_id)
    _write_locales(session, payload)
    _write_entries(session, payload)
    _replace_docs(
        session, payload.provider_id, payload.docs if payload.kind == LANGUAGE_PACK else {}
    )
    bump_revision(session)


def _replace_children(session: Session, provider_id: str) -> None:
    for model in (I18nProviderCatalog, I18nProviderLocale, I18nProviderDoc):
        session.execute(delete(model).where(model.provider_id == provider_id))


def _write_locales(session: Session, payload: ProviderPayload) -> None:
    seen: set[str] = set()
    for locale in payload.locales:
        canonical = canonical_tag(locale.tag)
        if canonical is None:
            raise ValueError(f"invalid locale tag: {locale.tag!r}")
        if canonical in seen:
            continue
        seen.add(canonical)
        session.add(
            I18nProviderLocale(
                provider_id=payload.provider_id,
                tag=locale.tag,
                canonical=canonical,
                name=locale.name,
                native_name=locale.native_name,
            )
        )


def _write_entries(session: Session, payload: ProviderPayload) -> None:
    overrides = set(payload.overrides)
    for locale, catalog in payload.catalogs.items():
        canonical = canonical_tag(locale)
        if canonical is None:
            raise ValueError(f"invalid locale tag: {locale!r}")
        for key in sorted(catalog):
            session.add(
                I18nProviderCatalog(
                    provider_id=payload.provider_id,
                    locale=canonical,
                    key=key,
                    value=catalog[key],
                    is_override=key in overrides,
                )
            )


def write_docs(session: Session, provider_id: str, docs: Mapping[str, Mapping[str, str]]) -> None:
    """Replace a provider's localized documentation and bump the revision."""
    _replace_docs(session, provider_id, docs)
    bump_revision(session)


def _replace_docs(
    session: Session, provider_id: str, docs: Mapping[str, Mapping[str, str]]
) -> None:
    session.execute(delete(I18nProviderDoc).where(I18nProviderDoc.provider_id == provider_id))
    for locale, topics in docs.items():
        canonical = canonical_tag(locale)
        if canonical is None:
            raise ValueError(f"invalid locale tag: {locale!r}")
        for topic in sorted(topics):
            session.add(
                I18nProviderDoc(
                    provider_id=provider_id,
                    locale=locale,
                    canonical=canonical,
                    topic=topic,
                    content=topics[topic],
                )
            )


def set_review_status(session: Session, provider_id: str, status: str) -> bool:
    """Mark a pack draft or reviewed; a draft stays installed but inactive."""
    if status not in REVIEW_STATUSES:
        raise ValueError(f"unknown review status: {status!r}")
    row = session.get(I18nProvider, provider_id)
    if row is None:
        return False
    row.review_status = status
    bump_revision(session)
    return True


def delete_provider(session: Session, provider_id: str) -> bool:
    """Remove every row of one provider and recompute the view through revision."""
    row = session.get(I18nProvider, provider_id)
    if row is None:
        return False
    _replace_children(session, provider_id)
    session.delete(row)
    session.flush()
    bump_revision(session)
    return True


# --------------------------------------------------------------------------- #
# resolution
# --------------------------------------------------------------------------- #


@dataclass(frozen=True)
class _ProviderRows:
    provider: I18nProvider
    entries: Mapping[str, Mapping[str, str]]
    overrides: Mapping[str, frozenset[str]]
    locales: tuple[I18nProviderLocale, ...]

    @property
    def active(self) -> bool:
        if self.provider.kind == EXTENSION:
            return True
        if self.provider.kind == LANGUAGE_PACK:
            return self.provider.review_status == REVIEWED
        return False


def _load_providers(session: Session) -> tuple[_ProviderRows, ...]:
    providers = list(session.scalars(select(I18nProvider).order_by(I18nProvider.id)))
    if not providers:
        return ()
    ids = [row.id for row in providers]
    entries: dict[str, dict[str, dict[str, str]]] = {pid: {} for pid in ids}
    overrides: dict[str, dict[str, set[str]]] = {pid: {} for pid in ids}
    for entry in session.scalars(
        select(I18nProviderCatalog)
        .where(I18nProviderCatalog.provider_id.in_(ids))
        .order_by(
            I18nProviderCatalog.provider_id, I18nProviderCatalog.locale, I18nProviderCatalog.key
        )
    ):
        entries[entry.provider_id].setdefault(entry.locale, {})[entry.key] = entry.value
        if entry.is_override:
            overrides[entry.provider_id].setdefault(entry.locale, set()).add(entry.key)
    locales: dict[str, list[I18nProviderLocale]] = {pid: [] for pid in ids}
    for locale in session.scalars(
        select(I18nProviderLocale)
        .where(I18nProviderLocale.provider_id.in_(ids))
        .order_by(I18nProviderLocale.provider_id, I18nProviderLocale.id)
    ):
        locales[locale.provider_id].append(locale)
    return tuple(
        _ProviderRows(
            provider=row,
            entries=entries[row.id],
            overrides={locale: frozenset(keys) for locale, keys in overrides[row.id].items()},
            locales=tuple(locales[row.id]),
        )
        for row in providers
    )


def _pack_order(rows: Iterable[_ProviderRows]) -> list[_ProviderRows]:
    """Ascending application order: higher priority last, then greater id."""
    return sorted(rows, key=lambda row: (row.provider.priority, row.provider.id))


def owner_catalogs(session: Session) -> dict[str, dict[str, str]]:
    """The text every catalog owner already defines per canonical tag.

    Owners are the core catalogs plus active extension providers. Packs and
    custom translations are deliberately excluded: a new pack may fill or
    override an owner key, but it must not be rejected because another pack
    filled the same gap earlier (D5/D6).
    """
    owners: dict[str, dict[str, str]] = {tag: dict(load_catalog(tag) or {}) for tag in CORE_LOCALES}
    rows = [row for row in _load_providers(session) if row.provider.kind == EXTENSION]
    for row in sorted(rows, key=lambda item: item.provider.id):
        for locale, entries in row.entries.items():
            canonical = canonical_tag(locale) or locale
            owners.setdefault(canonical, {}).update(entries)
    return owners


def snapshot(session: Session) -> Snapshot:
    """Resolve every installed locale from the stored provider rows."""
    rows = _load_providers(session)
    active = [row for row in rows if row.active]
    core_owner = {tag: dict(load_catalog(tag) or {}) for tag in CORE_LOCALES}
    extensions = [row for row in active if row.provider.kind == EXTENSION]
    packs = _pack_order(row for row in active if row.provider.kind == LANGUAGE_PACK)

    tags: list[str] = [canonical_tag(tag) or tag for tag in CORE_LOCALES]
    descriptors: list[dict[str, str]] = [locale_descriptor(tag) for tag in CORE_LOCALES]
    for pack in packs:
        for locale in pack.locales:
            if locale.canonical in tags:
                continue
            tags.append(locale.canonical)
            descriptors.append(
                {
                    "tag": locale.tag,
                    "name": locale.name,
                    "nativeName": locale.native_name,
                    "provider": pack.provider.id,
                }
            )

    custom: dict[str, dict[str, str]] = {}
    for row in session.scalars(select(I18nCustomTranslation).order_by(I18nCustomTranslation.id)):
        custom.setdefault(canonical_tag(row.locale) or row.locale, {})[row.key] = row.value

    views: dict[str, LocaleView] = {}
    for canonical in tags:
        messages: dict[str, str] = dict(core_owner.get(canonical, {}))
        for extension in sorted(extensions, key=lambda row: row.provider.id):
            messages.update(extension.entries.get(canonical, {}))
        overrides: dict[str, str] = {}
        for pack in packs:
            for key, value in pack.entries.get(canonical, {}).items():
                if key in pack.overrides.get(canonical, frozenset()):
                    overrides[key] = value
                    messages[key] = value
                elif key not in messages:
                    messages[key] = value
        for key, value in custom.get(canonical, {}).items():
            overrides[key] = value
            messages[key] = value
        display = next(
            (entry["tag"] for entry in descriptors if canonical_tag(entry["tag"]) == canonical),
            canonical,
        )
        views[canonical] = LocaleView(tag=display, messages=messages, overrides=overrides)

    return Snapshot(
        revision=revision(session),
        tags=tuple(tags),
        locale_views=views,
        descriptors=tuple(descriptors),
    )


def resolve_doc(
    session: Session, locale: str | None, topic: str, default_locale: str = DEFAULT_LOCALE
) -> DocHit | None:
    """A localized doc topic: locale (and parent) first, then the fallback chain."""
    rows = _load_providers(session)
    packs = [row for row in rows if row.active and row.provider.kind == LANGUAGE_PACK]
    if not packs:
        return None
    installed = {locale.canonical for row in packs for locale in row.locales} | set(CORE_LOCALES)
    snapshot = Snapshot(
        revision=0,
        tags=tuple(sorted(installed)),
        locale_views={},
        descriptors=(),
    )
    ordered = sorted(
        packs, key=lambda row: (-row.provider.priority, _descending_id(row.provider.id))
    )
    docs = {
        (row.provider.id, doc.canonical, doc.topic): doc
        for row in packs
        for doc in session.scalars(
            select(I18nProviderDoc)
            .where(I18nProviderDoc.provider_id == row.provider.id)
            .order_by(I18nProviderDoc.id)
        )
    }
    for tag in snapshot.fallback(locale, default_locale):
        for pack in ordered:
            doc = docs.get((pack.provider.id, tag, topic))
            if doc is not None:
                return DocHit(
                    locale=doc.locale,
                    topic=doc.topic,
                    content=doc.content,
                    provider=pack.provider.id,
                )
    return None


def _descending_id(value: str) -> tuple[int, ...]:
    """Sort key that orders ids descending inside a plain ``sorted`` call."""
    return tuple(-ord(character) for character in value)


# --------------------------------------------------------------------------- #
# installation custom translations (T7, highest D5 precedence)
# --------------------------------------------------------------------------- #


def custom_catalog(session: Session) -> dict[str, dict[str, str]]:
    """Every stored custom translation as ``locale -> key -> text``."""
    catalog: dict[str, dict[str, str]] = {}
    for row in session.scalars(
        select(I18nCustomTranslation).order_by(
            I18nCustomTranslation.locale, I18nCustomTranslation.key
        )
    ):
        catalog.setdefault(canonical_tag(row.locale) or row.locale, {})[row.key] = row.value
    return catalog


def set_custom_translations(session: Session, locale: str, entries: Mapping[str, str]) -> int:
    """Upsert custom translations for one locale; returns the changed row count.

    Unchanged values are not rewritten, so importing the same catalog twice is a
    no-op and does not bump the revision.
    """
    canonical = canonical_tag(locale)
    if canonical is None:
        raise ValueError(f"invalid locale tag: {locale!r}")
    existing = {
        row.key: row
        for row in session.scalars(
            select(I18nCustomTranslation).where(I18nCustomTranslation.locale == canonical)
        )
    }
    changed = 0
    for key in sorted(entries):
        value = entries[key]
        row = existing.get(key)
        if row is None:
            session.add(I18nCustomTranslation(locale=canonical, key=key, value=value))
            changed += 1
        elif row.value != value:
            row.value = value
            changed += 1
    if changed:
        bump_revision(session)
        session.flush()
    return changed


def delete_custom_translations(
    session: Session, locale: str, keys: Iterable[str] | None = None
) -> int:
    """Delete one custom translation or the whole locale layer; returns the count."""
    canonical = canonical_tag(locale)
    if canonical is None:
        raise ValueError(f"invalid locale tag: {locale!r}")
    statement = delete(I18nCustomTranslation).where(I18nCustomTranslation.locale == canonical)
    if keys is not None:
        wanted = sorted(set(keys))
        if not wanted:
            return 0
        statement = statement.where(I18nCustomTranslation.key.in_(wanted))
    result = session.execute(statement)
    deleted = int(result.rowcount or 0)
    if deleted:
        bump_revision(session)
        session.flush()
    return deleted


# --------------------------------------------------------------------------- #
# source catalogs registered at runtime (T7 ``PUT /i18n/sources/ui``)
# --------------------------------------------------------------------------- #


def _source_content(
    session: Session, provider_id: str
) -> tuple[dict[str, dict[str, str]], dict[str, str]]:
    catalogs: dict[str, dict[str, str]] = {}
    for entry in session.scalars(
        select(I18nProviderCatalog)
        .where(I18nProviderCatalog.provider_id == provider_id)
        .order_by(I18nProviderCatalog.locale, I18nProviderCatalog.key)
    ):
        catalogs.setdefault(entry.locale, {})[entry.key] = entry.value
    context = {
        row.key: row.context
        for row in session.scalars(
            select(I18nSourceContext)
            .where(I18nSourceContext.provider_id == provider_id)
            .order_by(I18nSourceContext.key)
        )
    }
    return catalogs, context


def source_digest(catalogs: Mapping[str, Mapping[str, str]], context: Mapping[str, str]) -> str:
    """Content hash of a normalized source payload; idempotency is by this hash."""
    normalized = {
        "catalogs": {
            locale: dict(sorted(catalog.items())) for locale, catalog in sorted(catalogs.items())
        },
        "context": dict(sorted(context.items())),
    }
    encoded = json.dumps(
        normalized, sort_keys=True, ensure_ascii=False, separators=(",", ":")
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def write_source_catalog(
    session: Session,
    provider_id: str,
    catalogs: Mapping[str, Mapping[str, str]],
    context: Mapping[str, str],
    *,
    version: str = "1.0.0",
) -> tuple[bool, str]:
    """Replace one source provider's catalogs and context; ``(changed, digest)``.

    Re-registering the same content is a no-op: no row is touched and the
    revision does not move, so a repeated frontend build keeps the bundle ETag.
    """
    normalized: dict[str, dict[str, str]] = {}
    for locale, catalog in catalogs.items():
        canonical = canonical_tag(locale)
        if canonical is None:
            raise ValueError(f"invalid locale tag: {locale!r}")
        target = normalized.setdefault(canonical, {})
        for key in sorted(catalog):
            target[key] = catalog[key]
    normalized_context = {str(key): str(value) for key, value in context.items()}
    digest = source_digest(normalized, normalized_context)

    stored_catalogs, stored_context = _source_content(session, provider_id)
    if source_digest(stored_catalogs, stored_context) == digest:
        return False, digest

    row = session.get(I18nProvider, provider_id)
    if row is None:
        row = I18nProvider(
            id=provider_id,
            kind=UI_SOURCE,
            version=version,
            priority=0,
            review_status=REVIEWED,
        )
        session.add(row)
    else:
        row.kind = UI_SOURCE
        row.version = version
        row.priority = 0
        row.review_status = REVIEWED
    session.flush()

    _replace_children(session, provider_id)
    session.execute(delete(I18nSourceContext).where(I18nSourceContext.provider_id == provider_id))
    for locale in sorted(normalized):
        for key in sorted(normalized[locale]):
            session.add(
                I18nProviderCatalog(
                    provider_id=provider_id,
                    locale=locale,
                    key=key,
                    value=normalized[locale][key],
                    is_override=False,
                )
            )
    for key in sorted(normalized_context):
        session.add(
            I18nSourceContext(provider_id=provider_id, key=key, context=normalized_context[key])
        )
    bump_revision(session)
    return True, digest


def source_catalogs(session: Session, provider_id: str | None = None) -> dict[str, dict[str, str]]:
    """Source text registered at runtime as ``locale -> key -> text``.

    Only ``ui-source`` providers are returned: extension and pack entries are
    overlay content and already appear in the resolved locale views.
    """
    providers = [
        row
        for row in session.scalars(select(I18nProvider).order_by(I18nProvider.id))
        if row.kind == UI_SOURCE and (provider_id is None or row.id == provider_id)
    ]
    merged: dict[str, dict[str, str]] = {}
    for provider in providers:
        catalogs, _ = _source_content(session, provider.id)
        for locale, catalog in catalogs.items():
            merged.setdefault(locale, {}).update(catalog)
    return merged


def source_context(session: Session, provider_id: str | None = None) -> dict[str, str]:
    """Translator context registered with a source catalog, merged by provider id."""
    providers = [
        row
        for row in session.scalars(select(I18nProvider).order_by(I18nProvider.id))
        if row.kind == UI_SOURCE and (provider_id is None or row.id == provider_id)
    ]
    merged: dict[str, str] = {}
    for provider in providers:
        _, context = _source_content(session, provider.id)
        merged.update(context)
    return merged


def extension_source_entries(session: Session, locale: str = DEFAULT_LOCALE) -> dict[str, str]:
    """The source-locale entries active extension providers own (``ext.<id>.*``)."""
    canonical = canonical_tag(locale) or locale
    entries: dict[str, str] = {}
    for row in sorted(
        (item for item in _load_providers(session) if item.provider.kind == EXTENSION),
        key=lambda item: item.provider.id,
    ):
        entries.update(row.entries.get(canonical, {}))
    return entries


# --------------------------------------------------------------------------- #
# coverage attribution
# --------------------------------------------------------------------------- #


@dataclass(frozen=True)
class Contribution:
    """One provider's supplied entries for a locale, for the translator report."""

    provider_id: str
    kind: str
    entries: int


def contributions(session: Session, canonical: str) -> tuple[Contribution, ...]:
    """Which providers supply entries for ``canonical``, in a stable order."""
    result: list[Contribution] = []
    if canonical in CORE_LOCALES:
        core = load_catalog(canonical)
        if core:
            result.append(Contribution(CORE_PROVIDER, CORE_PROVIDER, len(core)))
    rows = _load_providers(session)
    for row in rows:
        kind = row.provider.kind
        if kind == UI_SOURCE:
            count = len(row.entries.get(canonical, {}))
            if count:
                result.append(Contribution(row.provider.id, UI_SOURCE, count))
    for row in rows:
        if row.provider.kind != EXTENSION:
            continue
        count = len(row.entries.get(canonical, {}))
        if count:
            result.append(Contribution(row.provider.id, EXTENSION, count))
    for row in _pack_order(
        item for item in rows if item.active and item.provider.kind == LANGUAGE_PACK
    ):
        count = len(row.entries.get(canonical, {}))
        if count:
            result.append(Contribution(row.provider.id, LANGUAGE_PACK, count))
    custom = session.scalar(
        select(func.count())
        .select_from(I18nCustomTranslation)
        .where(I18nCustomTranslation.locale == canonical)
    )
    if custom:
        result.append(Contribution(CUSTOM, CUSTOM, int(custom)))
    return tuple(result)
