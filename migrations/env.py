"""Alembic environment: migrations run with the same settings as the app."""

from __future__ import annotations

from alembic import context
from itsm.config import get_settings
from itsm.database import create_engine_from_settings

config = context.config
target_metadata = None


def run_migrations_offline() -> None:
    settings = get_settings()
    context.configure(
        url=settings.database_url,
        target_metadata=target_metadata,
        literal_binds=True,
        dialect_opts={"paramstyle": "named"},
        compare_type=True,
    )
    with context.begin_transaction():
        context.run_migrations()


def run_migrations_online() -> None:
    settings = get_settings()
    engine = create_engine_from_settings(settings)
    try:
        with engine.connect() as connection:
            sqlite = connection.dialect.name == "sqlite"
            if sqlite:
                # The sqlite driver defers BEGIN until the first write statement and
                # autocommits DDL, so a revision that fails halfway would leave every
                # table it created committed and no way to retry ("table already
                # exists"). Take the write lock up front and commit once at the end:
                # all revisions and the version table then succeed or roll back
                # together. Alembic must stay out of the transaction management
                # here, because its SQLite dialect declares non-transactional DDL.
                connection.exec_driver_sql("BEGIN IMMEDIATE")
            context.configure(
                connection=connection,
                target_metadata=target_metadata,
                compare_type=True,
                transactional_ddl=False if sqlite else None,
                render_as_batch=sqlite,
            )
            try:
                with context.begin_transaction():
                    context.run_migrations()
            except BaseException:
                if sqlite:
                    connection.rollback()
                raise
            if sqlite:
                connection.commit()
    finally:
        engine.dispose()


if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()
