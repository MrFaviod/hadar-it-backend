"""SQLAlchemy models for the versioned catalog registry (T6a).

Owner catalogs (core files, extension packages) are never edited here: these
tables hold the installed *overlay* a provider contributes, plus the custom
translations a translator will own in T7. Every row set is provider-scoped so an
uninstall or an update recomputes the view instead of patching it in place.
"""

from __future__ import annotations

from datetime import datetime

from sqlalchemy import Boolean, DateTime, Index, Integer, String, Text, UniqueConstraint
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column

from itsm.identity.clock import utcnow


class I18nBase(DeclarativeBase):
    """Declarative base for the i18n registry tables."""


class I18nRegistryState(I18nBase):
    """Singleton row: the monotonic revision every catalog response carries."""

    __tablename__ = "i18n_registry_state"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    revision: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=utcnow, onupdate=utcnow
    )


class I18nProvider(I18nBase):
    """One installed extension or language pack that contributes catalogs."""

    __tablename__ = "i18n_providers"

    id: Mapped[str] = mapped_column(String(48), primary_key=True)
    kind: Mapped[str] = mapped_column(String(16), nullable=False)
    version: Mapped[str] = mapped_column(String(32), nullable=False)
    priority: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    review_status: Mapped[str] = mapped_column(String(16), nullable=False, default="reviewed")
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=utcnow
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=utcnow, onupdate=utcnow
    )


class I18nProviderCatalog(I18nBase):
    """One message a provider contributes for one locale."""

    __tablename__ = "i18n_provider_catalogs"
    __table_args__ = (
        UniqueConstraint("provider_id", "locale", "key", name="uq_i18n_provider_catalogs_entry"),
        Index("ix_i18n_provider_catalogs_locale", "locale"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    provider_id: Mapped[str] = mapped_column(String(48), nullable=False)
    locale: Mapped[str] = mapped_column(String(35), nullable=False)
    key: Mapped[str] = mapped_column(String(200), nullable=False)
    value: Mapped[str] = mapped_column(Text, nullable=False)
    is_override: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)


class I18nProviderLocale(I18nBase):
    """A locale a language pack installs; its public display names."""

    __tablename__ = "i18n_provider_locales"
    __table_args__ = (
        UniqueConstraint("provider_id", "tag", name="uq_i18n_provider_locales_tag"),
        Index("ix_i18n_provider_locales_tag", "tag"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    provider_id: Mapped[str] = mapped_column(String(48), nullable=False)
    tag: Mapped[str] = mapped_column(String(35), nullable=False)
    canonical: Mapped[str] = mapped_column(String(35), nullable=False)
    name: Mapped[str] = mapped_column(String(120), nullable=False)
    native_name: Mapped[str] = mapped_column(String(120), nullable=False)


class I18nProviderDoc(I18nBase):
    """One localized documentation topic shipped by a language pack."""

    __tablename__ = "i18n_provider_docs"
    __table_args__ = (
        UniqueConstraint("provider_id", "locale", "topic", name="uq_i18n_provider_docs_topic"),
        Index("ix_i18n_provider_docs_locale", "locale"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    provider_id: Mapped[str] = mapped_column(String(48), nullable=False)
    locale: Mapped[str] = mapped_column(String(35), nullable=False)
    canonical: Mapped[str] = mapped_column(String(35), nullable=False)
    topic: Mapped[str] = mapped_column(String(120), nullable=False)
    content: Mapped[str] = mapped_column(Text, nullable=False)


class I18nCustomTranslation(I18nBase):
    """Installation-level translation; highest precedence, written by T7."""

    __tablename__ = "i18n_custom_translations"
    __table_args__ = (UniqueConstraint("locale", "key", name="uq_i18n_custom_translations_entry"),)

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    locale: Mapped[str] = mapped_column(String(35), nullable=False)
    key: Mapped[str] = mapped_column(String(200), nullable=False)
    value: Mapped[str] = mapped_column(Text, nullable=False)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=utcnow, onupdate=utcnow
    )


class I18nSourceContext(I18nBase):
    """Translator context for a key registered by a *source* provider (T7).

    The core catalogs ship ``catalogs/context.json``; the frontend registers its
    ``ui.*`` source catalog over HTTP, so its context arrives the same way and
    needs a provider-scoped row set. Context is metadata only: it never changes
    a resolved message, it only describes where the text is used.
    """

    __tablename__ = "i18n_source_context"
    __table_args__ = (
        UniqueConstraint("provider_id", "key", name="uq_i18n_source_context_key"),
        Index("ix_i18n_source_context_provider", "provider_id"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    provider_id: Mapped[str] = mapped_column(String(48), nullable=False)
    key: Mapped[str] = mapped_column(String(200), nullable=False)
    context: Mapped[str] = mapped_column(Text, nullable=False)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=utcnow, onupdate=utcnow
    )
